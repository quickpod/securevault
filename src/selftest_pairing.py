#!/usr/bin/env python3
r"""
selftest_pairing - END TO END over a real vault: does the autofill service
actually refuse an unpaired caller, and actually serve a paired one?

selftest_auth.py proves the rules in svauth. It cannot prove that svpassgui
CALLS them - and "the gate exists but nothing routes through it" is the failure
that would matter most, because everything would look and behave completely
normally right up until someone asked for the passwords. So this drives the
real AutofillService._handle over a real encrypted vault, standing in for the
browser with a Python-side P-256 key.

Tk is imported (svpassgui pulls it in) but no window is ever created; the one
place the service touches the UI is stubbed out and asserted on.

    python selftest_pairing.py       (run from the src/ folder)
"""

import os, sys, base64, tempfile, shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import securevault as sv
import svtotp, svpass, svauth, svpassgui

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

fails = 0


def check(cond, msg):
    global fails
    print(("PASS" if cond else "FAIL"), msg)
    if not cond:
        fails += 1


class FakeApp:
    """Stands in for the Tk root. The service only ever uses .after() to push
    the save/update banner onto the UI thread; we record the calls instead."""
    def __init__(self):
        self.scheduled = []

    def after(self, _delay, fn):
        self.scheduled.append(fn)

    def winfo_children(self):
        return []


class FakeBrowser:
    """What the extension does, in Python: hold a P-256 key, and sign
    client_id|op|nonce|origin producing RAW r||s exactly like WebCrypto."""

    def __init__(self):
        self._priv = ec.generate_private_key(ec.SECP256R1())
        self.client_id = ""

    @property
    def pubkey(self):
        return base64.b64encode(self._priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

    def _sign(self, payload):
        der = self._priv.sign(payload, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()

    def call(self, svc, op, origin="", **extra):
        """A full privileged round trip: challenge, sign, request."""
        ch = svc._handle({"op": "challenge", "client_id": self.client_id})
        if not ch.get("ok"):
            return ch
        req = {"op": op, "origin": origin, "client_id": self.client_id,
               "nonce": ch["nonce"],
               "sig": self._sign(svauth.signed_payload(
                   self.client_id, op, origin, ch["nonce"]))}
        req.update(extra)
        return svc._handle(req)


# ------------------------------------------------------------------ fresh vault
tmp = tempfile.mkdtemp()
dat = os.path.join(tmp, "SecureVault.dat")
PW = sv.auth_material(b"correct horse battery staple", b"481920")
vault = sv.Vault(dat)
SECRET = vault.create(PW)
vault = sv.Vault(dat).unlock(PW, svtotp.totp(SECRET))

s = svpass.PasswordStore(vault)
s.load()
s.add(title="Bank", username="alex", password="Tr0ub4dor&3",
      url="https://bank.example.com/login")
s.save()

app = FakeApp()
svc = svpassgui.AutofillService(app, vault)
browser = FakeBrowser()

print("\n-- before pairing --")
ping = svc._handle({"op": "ping"})
check(ping.get("ok") and ping.get("paired") == 0, "ping works with nothing paired")

# The attack this system exists to stop: a local process holding the pipe token,
# speaking the wire format perfectly, asking for a password.
r = svc._handle({"op": "query", "origin": "https://bank.example.com"})
check(not r.get("ok"), "unpaired query REFUSED")
check(r.get("code") == "unpaired", "refusal is coded 'unpaired' for the UI")
check("logins" not in r, "refusal leaks no logins field")
check("Tr0ub4dor&3" not in repr(r), "refusal leaks no password material")

for op in ("identities", "generate", "save", "update"):
    check(not svc._handle({"op": op, "origin": "https://bank.example.com"}).get("ok"),
          f"unpaired {op} REFUSED")

check(not svc._handle({"op": "challenge", "client_id": "deadbeef"}).get("ok"),
      "challenge for an unknown client REFUSED")

# Registering without the user having armed a window in the app.
r = svc._handle({"op": "register", "pin": "123456", "pubkey": browser.pubkey})
check(not r.get("ok"), "register with no pairing window open REFUSED")

print("\n-- pairing --")
win = svc.arm_pairing()
wrong = "000000" if win.pin != "000000" else "111111"
r = svc._handle({"op": "register", "pin": wrong, "pubkey": browser.pubkey})
check(not r.get("ok"), "register with the wrong PIN REFUSED")
check(not svc.pairing_done(), "a wrong PIN leaves the window open to retry")

r = svc._handle({"op": "register", "pin": win.pin, "pubkey": browser.pubkey,
                 "label": "Chrome on Windows"})
check(r.get("ok") and r.get("client_id"), "register with the right PIN succeeds")
browser.client_id = r["client_id"]
check(svc.pairing_done(), "the pairing window closes after a successful pair")

r2 = svc._handle({"op": "register", "pin": win.pin, "pubkey": browser.pubkey})
check(not r2.get("ok"), "the PIN cannot be reused for a second browser")

print("\n-- paired --")
r = browser.call(svc, "query", "https://bank.example.com")
check(r.get("ok"), "paired query allowed")
check(len(r.get("logins", [])) == 1, "query returns the matching login")
check(r["logins"][0]["password"] == "Tr0ub4dor&3", "the password actually arrives")

r = browser.call(svc, "generate", "https://bank.example.com", length=20)
check(r.get("ok") and len(r.get("password", "")) == 20, "paired generate allowed")

r = browser.call(svc, "identities", "https://bank.example.com")
check(r.get("ok") and "alex" in r.get("usernames", []), "paired identities allowed")

r = browser.call(svc, "save", "https://new.example.com",
                 username="alex", password="brand-new-pw", url="https://new.example.com")
check(r.get("ok") and r.get("staged") == "save", "paired save is staged")
check(len(app.scheduled) == 1, "save was marshalled to the UI thread for confirmation")

print("\n-- the pairing survives a restart, the challenge does not --")
svc2 = svpassgui.AutofillService(FakeApp(), sv.Vault(dat).unlock(PW, svtotp.totp(SECRET)))
check(svc2._handle({"op": "ping"}).get("paired") == 1,
      "the pairing persisted into the encrypted vault blob")
r = browser.call(svc2, "query", "https://bank.example.com")
check(r.get("ok"), "the same browser still works after a restart")

# A challenge issued by one service instance must be worthless to another.
ch = svc._handle({"op": "challenge", "client_id": browser.client_id})
r = svc2._handle({"op": "query", "origin": "https://bank.example.com",
                  "client_id": browser.client_id, "nonce": ch["nonce"],
                  "sig": browser._sign(svauth.signed_payload(
                      browser.client_id, "query", "https://bank.example.com", ch["nonce"]))})
check(not r.get("ok"), "a challenge from another instance is REFUSED")

print("\n-- a second, rogue browser --")
rogue = FakeBrowser()
rogue.client_id = browser.client_id            # steal the (non-secret) id
r = rogue.call(svc, "query", "https://bank.example.com")
check(not r.get("ok"), "a rogue key using a valid client_id REFUSED")
check("Tr0ub4dor&3" not in repr(r), "rogue refusal leaks no password material")

print("\n-- revocation --")
check(svc.revoke_client(browser.client_id), "revoke reports success")
r = browser.call(svc, "query", "https://bank.example.com")
check(not r.get("ok") and r.get("code") == "unpaired",
      "the revoked browser is refused immediately")
svc3 = svpassgui.AutofillService(FakeApp(), sv.Vault(dat).unlock(PW, svtotp.totp(SECRET)))
check(svc3._handle({"op": "ping"}).get("paired") == 0, "revocation persisted")

shutil.rmtree(tmp, ignore_errors=True)
print("\n" + ("ALL PASS" if not fails else f"{fails} FAILED"))
sys.exit(1 if fails else 0)
