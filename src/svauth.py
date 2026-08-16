#!/usr/bin/env python3
r"""
svauth - extension registration (pairing) and per-request authentication for
         the SecureVault autofill bridge.

WHY THIS EXISTS
Before this module, ANY process running as this user could read the pipe token
from %LOCALAPPDATA%\SecureVault\autofill.token, connect to the autofill pipe of
an unlocked vault, and ask for passwords. The extension's identity was checked
by Chrome (allowed_origins) and by svhost (argv origin), but neither check is
worth anything to the vault: an attacker can simply launch svhost.exe itself
with our extension id as argv and speak the wire format on stdin. The vault had
no way to tell the real extension from anything else.

Registration fixes exactly that. The extension proves possession of a private
key that the vault has seen before and that the user approved once, by hand.

THE SHAPE OF IT
  1. PAIRING (once per browser profile, user-initiated IN THE APP)
     The user clicks "Pair a browser" in SecureVault. The vault generates a
     6-digit PIN and opens a 120-second window. The user types that PIN into
     the extension popup. The extension generates an ECDSA P-256 keypair whose
     PRIVATE HALF IS NON-EXTRACTABLE (WebCrypto extractable=false, kept in
     IndexedDB) and sends {pin, pubkey}. If the PIN matches, the public key is
     recorded in the ENCRYPTED vault blob and the extension gets a client_id.

     The vault issues the PIN, not the extension. That direction matters: a
     hostile local process cannot make a pairing prompt appear, so there is no
     dialog for the user to click through by reflex. If no window is open,
     register just fails.

  2. EVERY PRIVILEGED REQUEST AFTERWARDS
     challenge{client_id} -> 32 random bytes, single use, 30s, bound to that
     client. The extension signs

         client_id | op | origin | nonce

     and sends the signature along. No valid signature, no passwords. Binding
     op and origin into the signed payload means a captured signature for
     query|https://example.com cannot be replayed as query|https://bank.com,
     and single-use nonces mean it cannot be replayed at all.

WHAT THIS DOES AND DOES NOT BUY, PLAINLY
  DOES: a process holding the pipe token but not the private key can now do
        nothing but ping. Stealing the key means prying a non-extractable
        WebCrypto key out of Chrome's IndexedDB - real work, not a 3-line
        script. Revocation is immediate and per-browser.
  DOES NOT: make this a hard boundary against malware already running as this
        user. Nothing on Windows does; there is no process-identity ACL. Code
        injected INTO the browser can still ask the key to sign. This raises
        the cost a great deal and makes every pairing visible and revocable,
        which is the same bar KeePassXC and 1Password set.

No network, no sockets, no pickle. Pure computation over dicts so the whole
module is unit-testable without Tk, without a browser, and without a vault.
"""

import os, sys, time, json, hmac, base64, secrets, threading

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------- policy knobs
PIN_DIGITS        = 6
PAIR_WINDOW_SECS  = 120      # how long a displayed PIN stays valid
PAIR_MAX_ATTEMPTS = 3        # wrong PINs before the window is burned
NONCE_BYTES       = 32
NONCE_TTL_SECS    = 30
MAX_LIVE_NONCES   = 64       # per client; bounds memory against a nonce flood
MAX_LABEL_LEN     = 64

# Ops that need no registration. Deliberately tiny: "is the app up?" and the
# two steps of proving who you are. Everything that can read or write a
# credential is privileged.
OPEN_OPS       = frozenset({"ping", "register", "challenge"})
PRIVILEGED_OPS = frozenset({"query", "identities", "save", "update", "generate",
                            # favorites sync: bookmark snapshots are vault
                            # data - reading OR writing them takes the same
                            # signed, challenge-bound proof as a password
                            "bookmarks_save", "bookmarks_get", "bookmarks_status"})
ALL_OPS        = OPEN_OPS | PRIVILEGED_OPS


class AuthError(Exception):
    """Refusal reason safe to hand back over the pipe (no secrets in it)."""


class NotPaired(AuthError):
    """No registration for this client_id. Distinct from a bad signature so the
    extension can tell 'you must pair' from 'something is wrong' - and so a
    genuine first run offers pairing instead of showing a scary error."""


# ------------------------------------------------------------------ pairing PIN
def new_pin() -> str:
    """A uniformly random 6-digit PIN. secrets.randbelow, not random.randint:
    the latter is a Mersenne twister and predicting a pairing PIN would let a
    local process pair itself during a window the user opened for a browser."""
    return f"{secrets.randbelow(10 ** PIN_DIGITS):0{PIN_DIGITS}d}"


class PairingWindow:
    """One armed 'Pair a browser' window. Single use, expiring, rate limited.

    Held only in memory in the running GUI - a pairing window never touches
    disk, so it cannot outlive the process or be replayed from a crash dump of
    the vault file."""

    def __init__(self, ttl=PAIR_WINDOW_SECS, now=None):
        self.pin = new_pin()
        self.expires_at = (now or time.monotonic()) + ttl
        self.attempts_left = PAIR_MAX_ATTEMPTS
        self.used = False

    def seconds_left(self, now=None) -> int:
        return max(0, int(self.expires_at - (now or time.monotonic())))

    def alive(self, now=None) -> bool:
        return (not self.used and self.attempts_left > 0
                and (now or time.monotonic()) < self.expires_at)

    def redeem(self, pin: str, now=None) -> bool:
        """Consume one attempt. True only if this exact PIN is correct and the
        window is still live; the window is burned either way on success."""
        if not self.alive(now):
            raise AuthError("no pairing window is open - click "
                            "'Pair a browser' in SecureVault first")
        self.attempts_left -= 1
        # constant time: a timing oracle on 6 digits is a small search space
        if not hmac.compare_digest(str(pin or ""), self.pin):
            if self.attempts_left <= 0:
                self.used = True
                raise AuthError("too many wrong PINs - the pairing window is closed")
            raise AuthError(f"wrong PIN ({self.attempts_left} attempts left)")
        self.used = True
        return True


# ------------------------------------------------------------------- public key
def load_client_pubkey(spki_b64: str):
    """Parse a registered/offered public key, refusing anything that is not a
    P-256 ECDSA key. Without the curve check a client could register an RSA key
    or an exotic curve and steer verification somewhere we have not reasoned
    about; we accept exactly what the extension is specified to generate."""
    try:
        raw = base64.b64decode(spki_b64 or "", validate=True)
    except Exception:
        raise AuthError("public key is not valid base64")
    if not raw or len(raw) > 1024:
        raise AuthError("public key has an implausible size")
    try:
        pub = load_der_public_key(raw)
    except Exception:
        raise AuthError("public key is not a valid SPKI DER blob")
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise AuthError("public key is not an EC key")
    if not isinstance(pub.curve, ec.SECP256R1):
        raise AuthError(f"public key uses {pub.curve.name}, expected secp256r1")
    return pub


def signed_payload(client_id: str, op: str, origin: str, nonce: str) -> bytes:
    """Exactly what both sides sign. Field separator is '|', which cannot occur
    in a client_id (hex) or a nonce (hex); op comes from a fixed set. Only
    origin is attacker-influenced, and it is the LAST field, so no shifting of
    content between fields can forge a different (op, origin) pair."""
    return "|".join([client_id or "", op or "", nonce or "",
                     origin or ""]).encode("utf-8")


def verify_signature(spki_b64: str, payload: bytes, sig_b64: str) -> None:
    """Raise AuthError unless sig_b64 is a valid P-256 signature over payload.

    WebCrypto's ECDSA sign() emits the raw fixed-width r||s pair (64 bytes for
    P-256) from the JOSE/WebCrypto convention; `cryptography` wants a DER
    SEQUENCE. Converting here is not cosmetic - handing the raw pair straight
    to verify() fails every time, which is a very easy way to end up 'fixing'
    the problem by weakening the check."""
    try:
        raw = base64.b64decode(sig_b64 or "", validate=True)
    except Exception:
        raise AuthError("signature is not valid base64")
    if len(raw) != 64:
        raise AuthError(f"signature is {len(raw)} bytes, expected 64 (raw r||s)")
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    if r == 0 or s == 0:
        raise AuthError("malformed signature")
    pub = load_client_pubkey(spki_b64)
    try:
        pub.verify(encode_dss_signature(r, s), payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise AuthError("signature does not verify")


# -------------------------------------------------------------------- challenges
class ChallengeJar:
    """Server-issued, single-use, short-lived nonces, bound to one client_id.

    Single-use is what makes a captured request unreplayable; the TTL bounds
    how long a signature captured in flight stays interesting. Thread-safe
    because pipe requests arrive on a server worker thread."""

    def __init__(self, ttl=NONCE_TTL_SECS, cap=MAX_LIVE_NONCES):
        self.ttl = ttl
        self.cap = cap
        self._live = {}                      # client_id -> {nonce: expires_at}
        self._lock = threading.Lock()

    def _sweep(self, bag, now):
        for n in [n for n, exp in bag.items() if exp <= now]:
            bag.pop(n, None)

    def issue(self, client_id: str, now=None) -> str:
        now = now if now is not None else time.monotonic()
        nonce = secrets.token_hex(NONCE_BYTES)
        with self._lock:
            bag = self._live.setdefault(client_id, {})
            self._sweep(bag, now)
            if len(bag) >= self.cap:
                # drop the oldest rather than refuse: a flood of challenge calls
                # must not be able to lock the real extension out of autofill
                oldest = min(bag, key=bag.get)
                bag.pop(oldest, None)
            bag[nonce] = now + self.ttl
        return nonce

    def consume(self, client_id: str, nonce: str, now=None) -> None:
        """Raise AuthError unless this nonce is live for this client. Removes
        it, so a second use of the same nonce always fails."""
        now = now if now is not None else time.monotonic()
        with self._lock:
            bag = self._live.get(client_id) or {}
            self._sweep(bag, now)
            if not nonce or bag.pop(nonce, None) is None:
                raise AuthError("challenge is unknown, already used, or expired")

    def forget(self, client_id: str) -> None:
        with self._lock:
            self._live.pop(client_id, None)


# ------------------------------------------------------------- registered clients
# Persisted inside the encrypted password blob (PasswordStore.data["clients"]),
# so the list of paired browsers and their keys are protected by the master
# password like everything else, and a locked vault reveals nothing about them.

def _clean_label(label: str) -> str:
    label = "".join(ch for ch in str(label or "") if ch.isprintable())
    return label.strip()[:MAX_LABEL_LEN] or "browser"


def register_client(clients: dict, pubkey_b64: str, label: str,
                    origin: str = "", now_epoch=None) -> str:
    """Validate and record a newly paired extension. Returns its client_id.
    `clients` is mutated in place; the caller persists the store."""
    load_client_pubkey(pubkey_b64)                  # reject junk before storing
    for cid, c in clients.items():
        if c.get("pubkey") == pubkey_b64:
            # re-pairing the same browser (user re-ran it, or reinstalled and
            # kept the key): refresh rather than accumulate duplicate entries
            c["label"] = _clean_label(label)
            c["origin"] = origin or c.get("origin", "")
            c["paired_at"] = now_epoch if now_epoch is not None else time.time()
            return cid
    cid = secrets.token_hex(8)
    clients[cid] = {
        "pubkey": pubkey_b64,
        "label": _clean_label(label),
        "origin": origin or "",
        "paired_at": now_epoch if now_epoch is not None else time.time(),
        "last_used": 0,
    }
    return cid


def authorize(clients: dict, jar: "ChallengeJar", req: dict) -> dict:
    """The gate every privileged request passes through.

    Returns the client record on success; raises AuthError otherwise. Kept
    separate from the GUI handler so the rule can be tested directly and so
    there is exactly ONE place that decides whether a request is authorized."""
    op = req.get("op")
    if op not in PRIVILEGED_OPS:
        raise AuthError(f"not a privileged op: {op!r}")
    cid = req.get("client_id") or ""
    client = clients.get(cid)
    if not client:
        raise NotPaired("this browser is not paired with SecureVault")
    # consume FIRST so a wrong signature still burns the nonce - otherwise a
    # caller could grind signature guesses against one long-lived challenge
    jar.consume(cid, req.get("nonce") or "")
    verify_signature(client["pubkey"],
                     signed_payload(cid, op, req.get("origin", ""),
                                    req.get("nonce", "")),
                     req.get("sig") or "")
    client["last_used"] = time.time()
    return client
