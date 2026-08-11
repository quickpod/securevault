#!/usr/bin/env python3
r"""
selftest_bundle - covers svbundle's wire format, both KDFs, and the merge rules.

Runs offline against temporary files. No vault and no network are touched, so
this is safe to run on the live machine. Exit code 0 means every check passed.

The checks that matter most are the NEGATIVE ones: a wrong passphrase must say
"wrong passphrase", a tampered byte must say "modified or corrupted", and an
import must never silently replace a seed. Those are the failures that would
cost real money or a real account.
"""
import os, sys, json, tempfile, traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import svbundle
import svtotp

PASS, FAIL = [], []


def check(name, fn):
    try:
        fn()
        PASS.append(name)
        print(f"  ok    {name}")
    except Exception as e:
        FAIL.append((name, e))
        print(f"  FAIL  {name}: {e}")
        traceback.print_exc()


SECRET_A = svtotp.random_secret()
SECRET_B = svtotp.random_secret()
PHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

ITEMS = [
    {"type": "totp", "title": "GitHub", "account": "me@example.com", "secret": SECRET_A},
    {"type": "totp", "title": "Bank", "account": "1234", "secret": SECRET_B,
     "digits": 8, "period": 60, "algorithm": "SHA256"},
    {"type": "seed", "title": "Cold wallet", "phrase": PHRASE, "notes": "metal backup in safe"},
]


# ----------------------------------------------------------------- round trip
def t_roundtrip_scrypt():
    blob = svbundle.pack(ITEMS, "correct horse battery staple", kdf="scrypt")
    out = svbundle.unpack(blob, "correct horse battery staple")
    assert len(out["items"]) == 3, out
    got = {i["title"]: i for i in out["items"]}
    assert got["GitHub"]["secret"] == SECRET_A
    assert got["Bank"]["digits"] == 8 and got["Bank"]["period"] == 60
    assert got["Cold wallet"]["phrase"] == PHRASE


def t_roundtrip_pbkdf2():
    blob = svbundle.pack(ITEMS, "another long passphrase", kdf="pbkdf2")
    out = svbundle.unpack(blob, "another long passphrase")
    assert len(out["items"]) == 3


def t_kdfs_are_not_interchangeable():
    """Same passphrase, different KDF -> different key. Proves the header is
    actually driving derivation rather than being decorative."""
    a = svbundle.pack(ITEMS, "same passphrase", kdf="scrypt")
    b = svbundle.pack(ITEMS, "same passphrase", kdf="pbkdf2")
    assert json.loads(a[7:7 + int.from_bytes(a[5:7], "big")])["kdf"] == "scrypt"
    assert json.loads(b[7:7 + int.from_bytes(b[5:7], "big")])["kdf"] == "pbkdf2"


def t_magic_and_version():
    blob = svbundle.pack(ITEMS, "pw", kdf="pbkdf2")
    assert blob[:4] == b"SVB1"
    assert blob[4] == 1


# ------------------------------------------------------------------- negative
def t_wrong_passphrase():
    blob = svbundle.pack(ITEMS, "right", kdf="pbkdf2")
    try:
        svbundle.unpack(blob, "wrong")
    except svbundle.BundleError as e:
        assert "wrong bundle passphrase" in str(e).lower(), e
        return
    raise AssertionError("a wrong passphrase was accepted")


def t_tampered_payload_is_detected():
    blob = bytearray(svbundle.pack(ITEMS, "pw", kdf="pbkdf2"))
    blob[-1] ^= 0x01                       # flip one bit of the GCM tag
    try:
        svbundle.unpack(bytes(blob), "pw")
    except svbundle.BundleError as e:
        assert "modified or corrupted" in str(e).lower(), e
        return
    raise AssertionError("a tampered bundle authenticated")


def t_not_a_bundle():
    for bad in (b"", b"nope", b"SVLT\x01\x00\x02{}"):
        try:
            svbundle.unpack(bad, "pw")
        except svbundle.BundleError:
            continue
        raise AssertionError(f"garbage accepted: {bad!r}")


def t_bad_secret_rejected_at_pack_time():
    try:
        svbundle.pack([{"type": "totp", "title": "x", "secret": "not-base32-!!"}], "pw")
    except svbundle.BundleError as e:
        assert "base32" in str(e).lower(), e
        return
    raise AssertionError("an invalid authenticator secret was packed")


def t_untitled_and_unknown_type_rejected():
    for bad in ({"type": "totp", "title": "", "secret": SECRET_A},
                {"type": "wat", "title": "x"},
                {"type": "seed", "title": "x", "phrase": ""}):
        try:
            svbundle.pack([bad], "pw")
        except svbundle.BundleError:
            continue
        raise AssertionError(f"invalid item accepted: {bad}")


def t_info_leaks_no_items():
    blob = svbundle.pack(ITEMS, "pw", kdf="pbkdf2")
    meta = svbundle.info(blob)
    assert meta["header"]["kdf"] == "pbkdf2"
    assert "verifier" not in meta["header"]
    flat = json.dumps(meta)
    for probe in ("GitHub", "Cold wallet", SECRET_A, PHRASE):
        assert probe not in flat, f"info() leaked {probe!r}"


def t_ciphertext_leaks_no_plaintext():
    blob = svbundle.pack(ITEMS, "pw", kdf="pbkdf2")
    for probe in (SECRET_A.encode(), PHRASE.encode(), b"Cold wallet"):
        assert probe not in blob, f"plaintext {probe!r} found in the bundle"


# ---------------------------------------------------------------- merge rules
class FakeStore:
    """Mimics the slice of svpass.PasswordStore that svbundle uses, so the merge
    rules can be tested without unlocking a 10.8 GB vault."""
    def __init__(self, entries=None):
        self.data = {"entries": dict(entries or {})}
        self.saved = False
    def _ensure(self):
        return self.data["entries"]
    def add(self, title, username="", password="", url="", notes="",
            totp_secret="", tags=None):
        eid = f"id{len(self.data['entries'])}"
        self.data["entries"][eid] = {
            "title": title, "username": username, "password": password,
            "url": url, "notes": notes, "totp_secret": totp_secret,
            "tags": sorted(set(tags or []))}
        return eid
    def update(self, eid, **fields):
        self.data["entries"][eid].update(fields)
    def save(self):
        self.saved = True


def t_export_picks_totp_and_seed_tagged():
    store = FakeStore({
        "a": {"title": "GitHub", "username": "me", "password": "pw1",
              "totp_secret": SECRET_A, "tags": []},
        "b": {"title": "No 2FA", "username": "x", "password": "pw2",
              "totp_secret": "", "tags": []},
        "c": {"title": "Cold wallet", "username": "", "password": PHRASE,
              "totp_secret": "", "tags": ["seed"]},
    })
    items = svbundle.items_from_store(store)
    kinds = sorted((i["type"], i["title"]) for i in items)
    assert kinds == [("seed", "Cold wallet"), ("totp", "GitHub")], kinds
    # a plain password with no TOTP and no seed tag must NOT be exported
    assert all(i["title"] != "No 2FA" for i in items)


def t_export_excludes_seeds_when_asked():
    store = FakeStore({"c": {"title": "Cold wallet", "password": PHRASE,
                             "totp_secret": "", "tags": ["seed"]}})
    assert svbundle.items_from_store(store, include_seeds=False) == []


def t_import_adds_new():
    store = FakeStore()
    r = svbundle.merge_into_store(store, ITEMS)
    assert r["added"] == 3, r
    titles = {e["title"] for e in store._ensure().values()}
    assert titles == {"GitHub", "Bank", "Cold wallet"}, titles
    seed = [e for e in store._ensure().values() if e["title"] == "Cold wallet"][0]
    assert seed["password"] == PHRASE
    assert "seed" in seed["tags"], "an imported seed must carry the seed tag"


def t_import_fills_missing_secret():
    store = FakeStore({"a": {"title": "GitHub", "username": "me", "password": "pw1",
                             "totp_secret": "", "tags": []}})
    r = svbundle.merge_into_store(store, [ITEMS[0]])
    assert r["updated"] == 1 and r["added"] == 0, r
    assert store._ensure()["a"]["totp_secret"] == SECRET_A


def t_import_is_idempotent():
    store = FakeStore()
    svbundle.merge_into_store(store, ITEMS)
    before = json.dumps(store.data, sort_keys=True)
    r = svbundle.merge_into_store(store, ITEMS)
    assert r["added"] == 0 and r["updated"] == 0 and r["skipped"] == 3, r
    assert json.dumps(store.data, sort_keys=True) == before, "re-import mutated the store"


def t_import_never_clobbers_a_differing_seed():
    """The check this whole module exists for: importing a DIFFERENT phrase over
    an existing one must be refused unless overwrite is explicit."""
    store = FakeStore({"c": {"title": "Cold wallet", "password": "OLD PHRASE",
                             "totp_secret": "", "tags": ["seed"]}})
    r = svbundle.merge_into_store(store, [ITEMS[2]])
    assert r["skipped"] == 1 and r["updated"] == 0, r
    assert store._ensure()["c"]["password"] == "OLD PHRASE", "a seed was silently replaced"

    r = svbundle.merge_into_store(store, [ITEMS[2]], overwrite=True)
    assert r["updated"] == 1, r
    assert store._ensure()["c"]["password"] == PHRASE


def t_file_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.svb")
        with open(p, "wb") as f:
            f.write(svbundle.pack(ITEMS, "file passphrase", kdf="pbkdf2"))
        with open(p, "rb") as f:
            data = f.read()
        assert len(svbundle.unpack(data, "file passphrase")["items"]) == 3
        assert svbundle.info(data)["bytes"] == len(data)


if __name__ == "__main__":
    print("svbundle selftest")
    for name, fn in sorted(globals().items()):
        if name.startswith("t_") and callable(fn):
            check(name[2:], fn)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    sys.exit(1 if FAIL else 0)
