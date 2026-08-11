#!/usr/bin/env python3
r"""
svhost - Chrome/Edge native-messaging host for SecureVault autofill.

The browser launches this process and speaks the native-messaging wire format
on stdio: each message is a 4-byte little-endian length prefix followed by that
many bytes of UTF-8 JSON. We translate each message into an svipc pipe call to
the running, unlocked SecureVault GUI and write the reply back in the same
framing.

This process HOLDS NO KEYS. It cannot decrypt anything. If the GUI is not open
and unlocked, every call returns {"ok": false, "error": "SecureVault is not
open/unlocked"} and the extension shows "unlock SecureVault to autofill".

The browser passes the calling extension's origin as argv[1]
(chrome-extension://<id>/). We refuse to run unless it matches the origin we
were registered for - a second check on top of the manifest's allowed_origins.

BE CLEAR ABOUT WHAT THAT ORIGIN CHECK IS WORTH: nothing, against a local
attacker. Anyone running as this user can launch this host themselves and pass
our extension id as argv. That is precisely why the vault does not trust it.
Authorization lives in svauth: the extension must have been PAIRED with a PIN
the user read off the app, and must sign a fresh vault-issued challenge on
every request that touches a credential. This relay just carries the fields.

CRITICAL: nothing may be written to stdout except framed replies. All logging
goes to stderr, which the browser ignores.
"""

import os, sys, json, struct

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import svipc

# Written by the installer into a STABLE per-user dir (not next to this file):
# when frozen one-file, __file__ points at a temp extraction dir, so a path
# relative to it would vanish. This location is the same one svipc uses for the
# token. Contains [{"origin": "chrome-extension://<id>/"}].
ALLOWED_PATH = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                            "SecureVault", "svhost_allowed.json")


def _log(*a):
    print("svhost:", *a, file=sys.stderr, flush=True)


def _read_msg():
    raw_len = sys.stdin.buffer.read(4)
    if len(raw_len) < 4:
        return None                       # EOF - browser closed the port
    (n,) = struct.unpack("<I", raw_len)
    if n == 0 or n > 8 * 1024 * 1024:
        return None
    data = sys.stdin.buffer.read(n)
    return json.loads(data.decode("utf-8"))


def _write_msg(obj):
    data = json.dumps(obj).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(data)))
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def _allowed_origins():
    try:
        with open(ALLOWED_PATH, "r", encoding="utf-8") as f:
            return {e.get("origin", "").rstrip("/") for e in json.load(f)}
    except Exception:
        return set()


def _caller_origin():
    # Chrome/Edge pass the extension origin as the last argv on launch.
    for a in sys.argv[1:]:
        if a.startswith("chrome-extension://"):
            return a.rstrip("/")
    return ""


# ops the extension may relay; anything else is refused here, before the pipe
_RELAY_OPS = {"ping", "register", "challenge",
              "query", "save", "update", "generate", "identities"}

# Fields copied through to the vault. A whitelist, not a passthrough: the relay
# decides the shape of what reaches the handler, so a malformed or padded
# message from the browser cannot smuggle extra keys into the request dict.
_RELAY_FIELDS = ("op", "origin", "username", "password", "url", "length",
                 # pairing + per-request authentication (svauth)
                 "pin", "pubkey", "label", "client_id", "nonce", "sig")


def main():
    allowed = _allowed_origins()
    caller = _caller_origin()
    if allowed and caller and caller not in allowed:
        _log(f"refusing unknown caller origin {caller!r}")
        _write_msg({"ok": False, "error": "caller not allowed"})
        return 1

    while True:
        try:
            msg = _read_msg()
        except Exception as ex:
            _log("read error", ex)
            return 1
        if msg is None:
            return 0
        op = (msg or {}).get("op")
        if op not in _RELAY_OPS:
            _write_msg({"ok": False, "error": f"unsupported op {op!r}"})
            continue
        # attach the verified caller so the GUI can log/confirm against it
        req = {k: msg[k] for k in _RELAY_FIELDS if k in msg}
        req["caller"] = caller
        reply = svipc.call(req)
        _write_msg(reply)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as ex:
        _log("fatal", ex)
        try:
            _write_msg({"ok": False, "error": "host crashed"})
        except Exception:
            pass
        sys.exit(1)
