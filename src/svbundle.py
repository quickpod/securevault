#!/usr/bin/env python3
r"""
svbundle - a small, portable, self-contained encrypted bundle of secrets that
           moves between SecureVault on Windows and the iPhone vault.

WHY THIS EXISTS AND WHY IT IS NOT JUST A COPY OF THE .dat
SecureVault.dat is ~10.8 GB and its keys are wrapped by password + PIN + TOTP.
None of that travels to a phone. What travels is a FEW KILOBYTES of authenticator
seeds and recovery phrases, and it has to be openable by a program that has no
access to the vault at all. So this format is deliberately standalone:

  - one file, no index, no container, no dependency on SecureVault.dat
  - one passphrase, stretched by a KDF named IN THE HEADER
  - AES-256-GCM over a single JSON payload

It reuses SecureVault's primitives (`securevault.pw_material`, `derive_kek`,
`gcm_encrypt/gcm_decrypt`) rather than inventing anything. Importing this module
also imports securevault, which neuters sockets at import time, so nothing here
can reach the network even accidentally.

THE KDF CHOICE IS A PORTABILITY DECISION, NOT A SECURITY ONE
scrypt matches the vault's strength and is the default. But Apple's CryptoKit
has NO scrypt - a Swift reader needs a third-party implementation via SwiftPM.
PBKDF2-HMAC-SHA256 is in CommonCrypto on every iPhone and in Python's stdlib,
so `--kdf pbkdf2` produces a bundle any platform can open with zero
dependencies. The header names the KDF and carries its parameters, so a reader
never has to guess and old bundles keep working when the default changes.

Whichever you pick, THE BUNDLE IS ONLY AS STRONG AS ITS PASSPHRASE. Unlike the
vault there is no PIN and no TOTP standing in front of it - it is a file that
may sit in iCloud Drive or an inbox. Use a long passphrase, not a password.

WIRE FORMAT (implement exactly this in Swift; every integer is big-endian)
  [ 4 B ]  magic  b"SVB1"
  [ 1 B ]  format version (currently 1)
  [ 2 B ]  header length H
  [ H B ]  header JSON, UTF-8, no trailing newline. Keys:
             kdf        "scrypt" | "pbkdf2"
             salt       hex, 16 bytes
             verifier   hex, nonce||ct||tag over b"svbundle-ok", aad=b"verify"
             n, r, p                     (scrypt only)
             iterations, hash            (pbkdf2 only; hash is "sha256")
  [ rest ]  payload blob: nonce(12) || ciphertext || tag(16),
            AES-256-GCM, aad = b"svb1-payload", plaintext = payload JSON UTF-8

  key derivation, both KDFs:
     material = SHA-256(passphrase UTF-8)          <- the same input-boundary
                                                      reduction the vault does
     scrypt : key = scrypt(material, salt, N, r, p, dkLen=32)
     pbkdf2 : key = PBKDF2-HMAC-SHA256(material, salt, iterations, dkLen=32)

  The verifier exists so a wrong passphrase reports itself as a wrong
  passphrase instead of surfacing as a generic GCM authentication failure.

PAYLOAD JSON
  {"version": 1, "created": <unix int>, "items": [ ... ]}

  every item has "type" and "title"; the rest depends on the type
    {"type":"totp","title":..,"issuer":..,"account":..,"secret":<base32>,
     "algorithm":"SHA1","digits":6,"period":30,"tags":[..]}
    {"type":"seed","title":..,"phrase":<words>,"notes":..,"tags":[..]}

  A "seed" is a BIP-39 recovery phrase. It is carried, never interpreted -
  nothing here derives an address, signs anything, or validates a wordlist.

WHERE SEEDS COME FROM ON THE WINDOWS SIDE
svpass entries have no dedicated seed field, and adding one would change the
store schema for every existing entry. Instead an entry TAGGED "seed" exports
as type "seed", carrying its `password` field as the phrase. That field is
already the secret-bearing one and is already withheld from list views, so the
handling it gets is the handling a phrase needs.

MEMORY HYGIENE, STATED HONESTLY
Python strings are immutable and garbage-collected; this module cannot wipe a
passphrase or a seed from RAM, and pretending otherwise would be worse than
saying so. Long-lived exposure belongs in the vault, not in this process.
"""

import os, sys, json, time, hashlib, struct

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import securevault as sv          # also disables sockets at import time
import svtotp

MAGIC = b"SVB1"
VERSION = 1
SALT_LEN = 16
PBKDF2_ITERATIONS = 600_000       # OWASP 2023 floor for PBKDF2-HMAC-SHA256
VERIFY_PLAINTEXT = b"svbundle-ok"


class BundleError(Exception): pass


# ------------------------------------------------------------------------ kdf
def _derive(passphrase: str, salt: bytes, header: dict) -> bytes:
    """Header-driven so a reader never guesses. Unknown KDF is a hard error -
    silently falling back to a weaker one would be the worst possible failure."""
    material = sv.pw_material(passphrase.encode("utf-8"))
    kdf = header.get("kdf")
    if kdf == "scrypt":
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        return Scrypt(salt=salt, length=32, n=int(header["n"]),
                      r=int(header["r"]), p=int(header["p"])).derive(material)
    if kdf == "pbkdf2":
        if header.get("hash") != "sha256":
            raise BundleError(f"unsupported pbkdf2 hash: {header.get('hash')!r}")
        return hashlib.pbkdf2_hmac("sha256", material, salt,
                                   int(header["iterations"]), 32)
    raise BundleError(f"unsupported kdf: {kdf!r}")


def _new_header(kdf: str, salt: bytes) -> dict:
    if kdf == "scrypt":
        return {"kdf": "scrypt", "n": sv.SCRYPT_N, "r": sv.SCRYPT_R,
                "p": sv.SCRYPT_P, "salt": salt.hex()}
    if kdf == "pbkdf2":
        return {"kdf": "pbkdf2", "iterations": PBKDF2_ITERATIONS,
                "hash": "sha256", "salt": salt.hex()}
    raise BundleError(f"unsupported kdf: {kdf!r}")


# --------------------------------------------------------------- pack / unpack
def pack(items, passphrase: str, kdf: str = "scrypt") -> bytes:
    if not passphrase:
        raise BundleError("a bundle passphrase is required")
    salt = os.urandom(SALT_LEN)
    header = _new_header(kdf, salt)
    key = _derive(passphrase, salt, header)
    header["verifier"] = sv.gcm_encrypt(key, VERIFY_PLAINTEXT, b"verify").hex()

    payload = {"version": VERSION, "created": int(time.time()),
               "items": [validate_item(i) for i in items]}
    blob = sv.gcm_encrypt(key, json.dumps(payload, sort_keys=True).encode("utf-8"),
                          b"svb1-payload")

    hb = json.dumps(header, sort_keys=True).encode("utf-8")
    if len(hb) > 0xFFFF:
        raise BundleError("header too large")
    return MAGIC + bytes([VERSION]) + struct.pack(">H", len(hb)) + hb + blob


def unpack(data: bytes, passphrase: str) -> dict:
    if len(data) < 7 or data[:4] != MAGIC:
        raise BundleError("not a SecureVault bundle (bad magic)")
    ver = data[4]
    if ver != VERSION:
        raise BundleError(f"unsupported bundle version {ver}")
    (hlen,) = struct.unpack(">H", data[5:7])
    if len(data) < 7 + hlen:
        raise BundleError("truncated bundle (header)")
    header = json.loads(data[7:7 + hlen].decode("utf-8"))
    blob = data[7 + hlen:]
    if len(blob) <= sv.NONCE_LEN + 16:
        raise BundleError("truncated bundle (payload)")

    key = _derive(passphrase, bytes.fromhex(header["salt"]), header)
    try:
        if sv.gcm_decrypt(key, bytes.fromhex(header["verifier"]), b"verify") != VERIFY_PLAINTEXT:
            raise ValueError
    except Exception:
        raise BundleError("wrong bundle passphrase")
    try:
        payload = json.loads(sv.gcm_decrypt(key, blob, b"svb1-payload").decode("utf-8"))
    except BundleError:
        raise
    except Exception:
        # verifier passed but the body did not authenticate -> not a wrong
        # passphrase, this file has been altered or corrupted in transit
        raise BundleError("bundle failed authentication - it has been modified or corrupted")
    if payload.get("version") != VERSION:
        raise BundleError(f"unsupported payload version {payload.get('version')}")
    payload.setdefault("items", [])
    return payload


def info(data: bytes) -> dict:
    """What can be learned WITHOUT the passphrase: the KDF and its cost. Item
    count and titles are inside the encrypted payload and stay there."""
    if len(data) < 7 or data[:4] != MAGIC:
        raise BundleError("not a SecureVault bundle (bad magic)")
    (hlen,) = struct.unpack(">H", data[5:7])
    header = json.loads(data[7:7 + hlen].decode("utf-8"))
    header.pop("verifier", None)
    return {"version": data[4], "bytes": len(data), "header": header}


# ------------------------------------------------------------------ item model
def validate_item(item: dict) -> dict:
    t = item.get("type")
    title = (item.get("title") or "").strip()
    if not title:
        raise BundleError("every item needs a title")
    if t == "totp":
        secret = (item.get("secret") or "").strip().replace(" ", "").upper()
        if not secret:
            raise BundleError(f"{title}: totp item has no secret")
        try:
            svtotp.totp(secret)          # fail here, not on the phone at 3am
        except Exception:
            raise BundleError(f"{title}: not a valid base32 authenticator secret")
        return {"type": "totp", "title": title,
                "issuer": item.get("issuer", ""), "account": item.get("account", ""),
                "secret": secret,
                "algorithm": (item.get("algorithm") or "SHA1").upper(),
                "digits": int(item.get("digits") or 6),
                "period": int(item.get("period") or 30),
                "tags": sorted(set(item.get("tags") or []))}
    if t == "seed":
        phrase = (item.get("phrase") or "").strip()
        if not phrase:
            raise BundleError(f"{title}: seed item has no phrase")
        return {"type": "seed", "title": title, "phrase": phrase,
                "notes": item.get("notes", ""),
                "tags": sorted(set(item.get("tags") or []))}
    raise BundleError(f"{title or '<untitled>'}: unknown item type {t!r}")


def items_from_store(store, include_seeds: bool = True) -> list:
    """Every svpass entry carrying an authenticator secret, plus every entry
    tagged 'seed'. Passwords themselves are NOT exported - this bundle is for
    the secrets that cannot be reset, not the ones that can."""
    out = []
    for eid, e in (store._ensure()).items():
        tags = e.get("tags") or []
        if e.get("totp_secret"):
            out.append(validate_item({
                "type": "totp", "title": e.get("title") or eid,
                "issuer": e.get("title") or "", "account": e.get("username") or "",
                "secret": e["totp_secret"], "tags": tags}))
        if include_seeds and "seed" in tags and e.get("password"):
            out.append(validate_item({
                "type": "seed", "title": e.get("title") or eid,
                "phrase": e["password"], "notes": e.get("notes", ""), "tags": tags}))
    out.sort(key=lambda i: (i["type"], i["title"].lower()))
    return out


def merge_into_store(store, items, overwrite: bool = False) -> dict:
    """Import is ADDITIVE and never destructive: an existing entry is only
    touched when it is missing the secret being imported, unless -overwrite is
    passed. Losing a seed to a careless import is unrecoverable, so the default
    refuses rather than replaces."""
    entries = store._ensure()
    by_title = {}
    for eid, e in entries.items():
        by_title.setdefault((e.get("title") or "").strip().lower(), eid)

    added = updated = skipped = 0
    for item in items:
        item = validate_item(item)
        key = item["title"].strip().lower()
        eid = by_title.get(key)
        field = "totp_secret" if item["type"] == "totp" else "password"
        value = item["secret"] if item["type"] == "totp" else item["phrase"]

        if eid is None:
            kw = {"title": item["title"], "tags": item.get("tags") or []}
            if item["type"] == "totp":
                kw["username"] = item.get("account", "")
                kw["totp_secret"] = value
            else:
                kw["password"] = value
                kw["notes"] = item.get("notes", "")
                kw["tags"] = sorted(set(kw["tags"] + ["seed"]))
            new_id = store.add(**kw)
            by_title[key] = new_id
            added += 1
            continue

        existing = entries[eid].get(field) or ""
        if existing == value:
            skipped += 1
        elif existing and not overwrite:
            skipped += 1
        else:
            store.update(eid, **{field: value})
            updated += 1
    return {"added": added, "updated": updated, "skipped": skipped}


# -------------------------------------------------------------------- cli glue
USAGE = """svbundle - portable encrypted secret bundle (.svb)

  export <out.svb> [--kdf scrypt|pbkdf2] [--no-seeds]
        Read the vault's password store, write every authenticator seed (and
        every entry tagged 'seed') to an encrypted bundle.

  import <in.svb> [--overwrite]
        Merge a bundle back into the vault's password store. Additive by
        default; --overwrite is required to replace a secret that differs.

  info <in.svb>
        Show the KDF and its cost. Needs no passphrase and reveals no items.

Environment (all optional; prompted when absent and a console exists):
  SECUREVAULT_DAT / SECUREVAULT_PW / SECUREVAULT_PIN / SECUREVAULT_TOTP
  SECUREVAULT_BUNDLE_PW   the BUNDLE passphrase - distinct from the vault's
"""


def _bundle_passphrase(confirm: bool) -> str:
    pw = os.environ.get("SECUREVAULT_BUNDLE_PW")
    if pw:
        return pw
    import getpass
    pw = getpass.getpass("Bundle passphrase: ")
    if confirm and pw != getpass.getpass("Confirm: "):
        raise BundleError("passphrases did not match")
    if not pw:
        raise BundleError("a bundle passphrase is required")
    return pw


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    cmd, rest = argv[0], argv[1:]

    if cmd == "info":
        if not rest:
            print(USAGE); return 2
        with open(rest[0], "rb") as f:
            print(json.dumps(info(f.read()), indent=2))
        return 0

    if cmd not in ("export", "import") or not rest:
        print(USAGE)
        return 2

    path = rest[0]
    flags = set(rest[1:])
    kdf = "scrypt"
    if "--kdf" in rest:
        kdf = rest[rest.index("--kdf") + 1]

    # Same door every other verb uses: securevault.open_vault() enforces
    # password + PIN + TOTP before it ever hands back a data key.
    import svpass
    vault = sv.open_vault()
    store = svpass.PasswordStore(vault)
    store.load()

    if cmd == "export":
        items = items_from_store(store, include_seeds="--no-seeds" not in flags)
        if not items:
            print("Nothing to export: no entry has an authenticator secret or a 'seed' tag.")
            return 1
        data = pack(items, _bundle_passphrase(confirm=True), kdf=kdf)
        with open(path, "wb") as f:
            f.write(data)
        totp_n = sum(1 for i in items if i["type"] == "totp")
        seed_n = sum(1 for i in items if i["type"] == "seed")
        print(f"Wrote {path}  ({len(data)} bytes, kdf={kdf}, "
              f"{totp_n} authenticator, {seed_n} seed)")
        print("This file is a credential. Its only protection is the passphrase you just typed.")
        return 0

    with open(path, "rb") as f:
        payload = unpack(f.read(), _bundle_passphrase(confirm=False))
    result = merge_into_store(store, payload["items"], overwrite="--overwrite" in flags)
    store.save()
    print(f"Imported: {result['added']} added, {result['updated']} updated, "
          f"{result['skipped']} skipped")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BundleError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
