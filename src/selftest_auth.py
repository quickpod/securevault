#!/usr/bin/env python3
r"""
selftest_auth - proves the extension registration + request-signing rules in
svauth.py, with no Tk, no browser, no vault and no pipe.

The point of these tests is the REFUSALS. It is easy to write a pairing system
that says yes to the right client; the whole value is in saying no to everything
else, so most of what follows asserts that a request is rejected.

    python selftest_auth.py          (run from the src/ folder)
"""

import os, sys, base64, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import svauth

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

PASS, FAIL = [], []


def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok' if cond else 'FAIL'}] {name}")


def refuses(name, fn, expect_type=svauth.AuthError):
    """Assert fn() raises. A test that only checks 'it did not return the
    passwords' would pass on a crash; we want a clean, typed refusal."""
    try:
        fn()
    except expect_type:
        check(name, True)
        return
    except Exception as ex:
        check(f"{name} (wrong exception: {type(ex).__name__}: {ex})", False)
        return
    check(f"{name} (no exception raised!)", False)


# ------------------------------------------------------------------ test keys
def make_client():
    """A stand-in for the extension: a P-256 key, an SPKI public half, and a
    sign() that emits RAW r||s exactly like WebCrypto does in the browser."""
    priv = ec.generate_private_key(ec.SECP256R1())
    spki = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

    def sign(payload: bytes) -> str:
        der = priv.sign(payload, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()

    return spki, sign, priv


def signed_req(cid, spki, sign, jar, op="query", origin="https://example.com",
               nonce=None):
    nonce = nonce if nonce is not None else jar.issue(cid)
    payload = svauth.signed_payload(cid, op, origin, nonce)
    return {"op": op, "origin": origin, "client_id": cid,
            "nonce": nonce, "sig": sign(payload)}


# ----------------------------------------------------------------- pairing PIN
def test_pin():
    print("\n-- pairing window --")
    w = svauth.PairingWindow()
    check("PIN is 6 digits", len(w.pin) == 6 and w.pin.isdigit())
    check("window starts alive", w.alive())

    w2 = svauth.PairingWindow()
    wrong = "000000" if w2.pin != "000000" else "111111"
    refuses("wrong PIN refused", lambda: w2.redeem(wrong))
    check("wrong PIN burns one attempt", w2.attempts_left == 2)
    check("window survives a wrong PIN", w2.alive())
    check("correct PIN redeems", w2.redeem(w2.pin) is True)
    check("window is single use", not w2.alive())
    refuses("redeemed window cannot be reused", lambda: w2.redeem(w2.pin))

    w3 = svauth.PairingWindow()
    wrong = "000000" if w3.pin != "000000" else "111111"
    for _ in range(svauth.PAIR_MAX_ATTEMPTS):
        try: w3.redeem(wrong)
        except svauth.AuthError: pass
    check("window burns after max attempts", not w3.alive())
    refuses("correct PIN is useless once burned", lambda: w3.redeem(w3.pin))

    # expiry, without sleeping: alive()/redeem() take an injectable clock
    w4 = svauth.PairingWindow(now=1000.0)
    check("alive before expiry", w4.alive(now=1000.0 + svauth.PAIR_WINDOW_SECS - 1))
    check("dead after expiry", not w4.alive(now=1000.0 + svauth.PAIR_WINDOW_SECS + 1))
    refuses("expired window refuses the right PIN",
            lambda: w4.redeem(w4.pin, now=1000.0 + svauth.PAIR_WINDOW_SECS + 1))

    pins = {svauth.new_pin() for _ in range(500)}
    check("PINs are not obviously fixed", len(pins) > 300)


# ------------------------------------------------------------------ public keys
def test_pubkeys():
    print("\n-- public key validation --")
    spki, _, _ = make_client()
    check("valid P-256 SPKI accepted", svauth.load_client_pubkey(spki) is not None)
    refuses("garbage base64 refused", lambda: svauth.load_client_pubkey("!!!!"))
    refuses("empty key refused", lambda: svauth.load_client_pubkey(""))
    refuses("valid base64 that is not a key refused",
            lambda: svauth.load_client_pubkey(base64.b64encode(b"hello").decode()))

    # An RSA key would verify under different rules than the ones reasoned
    # about here, so it is refused outright rather than handled.
    rsa_spki = base64.b64encode(
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key().public_bytes(serialization.Encoding.DER,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    refuses("RSA key refused", lambda: svauth.load_client_pubkey(rsa_spki))

    p384 = base64.b64encode(
        ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    refuses("wrong curve refused", lambda: svauth.load_client_pubkey(p384))


# ------------------------------------------------------------------- signatures
def test_signatures():
    print("\n-- signature verification --")
    spki, sign, _ = make_client()
    payload = svauth.signed_payload("abc", "query", "https://example.com", "ff00")

    # The WebCrypto/`cryptography` format mismatch: browsers emit raw r||s,
    # Python wants DER. If this ever regresses, EVERY request fails - which is
    # exactly the pressure that tempts someone to loosen the check instead.
    svauth.verify_signature(spki, payload, sign(payload))
    check("raw r||s signature from a browser verifies", True)

    refuses("tampered payload refused",
            lambda: svauth.verify_signature(
                spki, svauth.signed_payload("abc", "query", "https://evil.com", "ff00"),
                sign(payload)))

    other_spki, _, _ = make_client()
    refuses("signature from another key refused",
            lambda: svauth.verify_signature(other_spki, payload, sign(payload)))

    refuses("DER signature refused (wrong length)",
            lambda: svauth.verify_signature(
                spki, payload, base64.b64encode(b"\x30\x44" + b"\x00" * 68).decode()))
    refuses("empty signature refused",
            lambda: svauth.verify_signature(spki, payload, ""))
    refuses("zeroed signature refused",
            lambda: svauth.verify_signature(spki, payload,
                                            base64.b64encode(b"\x00" * 64).decode()))

    # Field separation: no rearrangement of the parts may produce the same bytes
    a = svauth.signed_payload("ab", "query", "https://x.com", "cd")
    b = svauth.signed_payload("ab|query", "", "https://x.com", "cd")
    check("payload fields cannot be shifted into one another", a != b)


# -------------------------------------------------------------------- challenges
def test_challenges():
    print("\n-- challenges --")
    jar = svauth.ChallengeJar()
    n = jar.issue("c1")
    check("nonce is 64 hex chars", len(n) == 64)
    jar.consume("c1", n)
    check("fresh nonce consumes once", True)
    refuses("replayed nonce refused", lambda: jar.consume("c1", n))
    refuses("unknown nonce refused", lambda: jar.consume("c1", "de" * 32))

    n2 = jar.issue("c1")
    refuses("nonce is bound to its client", lambda: jar.consume("c2", n2))

    jar2 = svauth.ChallengeJar(ttl=10)
    n3 = jar2.issue("c1", now=100.0)
    refuses("expired nonce refused", lambda: jar2.consume("c1", n3, now=111.0))

    jar3 = svauth.ChallengeJar()
    n4 = jar3.issue("c1")
    jar3.forget("c1")
    refuses("revoking a client drops its live nonces",
            lambda: jar3.consume("c1", n4))

    # A flood of challenge requests must not evict... itself into a lockout:
    # the newest nonce always survives, so the real extension still works.
    jar4 = svauth.ChallengeJar(cap=4)
    for _ in range(20):
        last = jar4.issue("c1")
    jar4.consume("c1", last)
    check("nonce flood does not lock out the newest challenge", True)


# ------------------------------------------------------------------- the gate
def test_authorize():
    print("\n-- authorize(): the gate --")
    clients = {}
    jar = svauth.ChallengeJar()
    spki, sign, _ = make_client()
    cid = svauth.register_client(clients, spki, "Chrome on Windows",
                                 "chrome-extension://abc/")
    check("registration returns a client id", bool(cid) and cid in clients)

    ok = svauth.authorize(clients, jar, signed_req(cid, spki, sign, jar))
    check("a properly signed request from a paired client is allowed",
          ok is clients[cid])

    # THE CASE THIS WHOLE MODULE EXISTS FOR: a local process that read the pipe
    # token and knows the wire format, but holds no registered key.
    refuses("unpaired caller refused",
            lambda: svauth.authorize(clients, jar,
                                     {"op": "query", "origin": "https://bank.com",
                                      "client_id": "", "nonce": "", "sig": ""}),
            svauth.NotPaired)
    refuses("made-up client_id refused",
            lambda: svauth.authorize(clients, jar,
                                     {"op": "query", "origin": "https://bank.com",
                                      "client_id": "deadbeef", "nonce": "x", "sig": "y"}),
            svauth.NotPaired)

    rogue_spki, rogue_sign, _ = make_client()
    refuses("a rogue key signing as a paired client_id refused",
            lambda: svauth.authorize(clients, jar,
                                     signed_req(cid, rogue_spki, rogue_sign, jar)))

    refuses("request with no signature refused",
            lambda: svauth.authorize(clients, jar,
                                     {"op": "query", "origin": "https://bank.com",
                                      "client_id": cid, "nonce": jar.issue(cid),
                                      "sig": ""}))

    # Replay: capture one valid request, resend it verbatim.
    req = signed_req(cid, spki, sign, jar)
    svauth.authorize(clients, jar, req)
    refuses("captured request cannot be replayed",
            lambda: svauth.authorize(clients, jar, dict(req)))

    # Origin swap: take a signature made for one site, aim it at another.
    req2 = signed_req(cid, spki, sign, jar, origin="https://example.com")
    req2["origin"] = "https://bank.com"
    refuses("signature cannot be redirected to another origin",
            lambda: svauth.authorize(clients, jar, req2))

    # Op swap: a signature made to read becomes an attempt to write.
    req3 = signed_req(cid, spki, sign, jar, op="query")
    req3["op"] = "save"
    refuses("signature cannot be upgraded to another op",
            lambda: svauth.authorize(clients, jar, req3))

    # A wrong signature must still consume the challenge, or a caller could
    # grind guesses against one long-lived nonce.
    n = jar.issue(cid)
    bad = signed_req(cid, rogue_spki, rogue_sign, jar, nonce=n)
    try: svauth.authorize(clients, jar, bad)
    except svauth.AuthError: pass
    refuses("a failed attempt burns the challenge",
            lambda: jar.consume(cid, n))

    refuses("open ops cannot be smuggled through the gate",
            lambda: svauth.authorize(clients, jar, {"op": "ping"}))
    refuses("unknown ops refused",
            lambda: svauth.authorize(clients, jar, {"op": "exfiltrate"}))

    # Revocation is what makes a lost laptop or a suspect browser recoverable.
    good = signed_req(cid, spki, sign, jar)
    clients.pop(cid)
    refuses("revoked client refused immediately",
            lambda: svauth.authorize(clients, jar, good), svauth.NotPaired)


def test_registration():
    print("\n-- registration bookkeeping --")
    clients = {}
    spki, _, _ = make_client()
    a = svauth.register_client(clients, spki, "Chrome")
    b = svauth.register_client(clients, spki, "Chrome renamed")
    check("re-pairing the same key reuses its id", a == b)
    check("re-pairing does not duplicate the record", len(clients) == 1)
    check("re-pairing refreshes the label", clients[a]["label"] == "Chrome renamed")

    spki2, _, _ = make_client()
    c = svauth.register_client(clients, spki2, "Edge")
    check("a second browser gets its own id", c != a and len(clients) == 2)

    refuses("registering a junk key refused",
            lambda: svauth.register_client(clients, "not-a-key", "x"))
    check("a refused registration stores nothing", len(clients) == 2)

    d = svauth.register_client(clients, make_client()[0], "x" * 500)
    check("absurd labels are truncated", len(clients[d]["label"]) <= svauth.MAX_LABEL_LEN)
    e = svauth.register_client(clients, make_client()[0], "\x00\x1b[31mevil")
    check("control characters stripped from labels",
          "\x00" not in clients[e]["label"] and "\x1b" not in clients[e]["label"])


if __name__ == "__main__":
    print("SecureVault - extension registration selftest")
    test_pin()
    test_pubkeys()
    test_signatures()
    test_challenges()
    test_authorize()
    test_registration()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        for f in FAIL:
            print("  FAILED:", f)
    sys.exit(1 if FAIL else 0)
