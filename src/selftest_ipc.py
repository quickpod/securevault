#!/usr/bin/env python3
r"""
selftest_ipc - the autofill TRANSPORT, hermetically: a fake vault handler on
one side, svipc (and a real svhost.py subprocess) on the other. No Tk, no
browser, no real vault, and a scratch address that never touches a running app.

What it proves, per platform (Windows named pipe / Linux AF_UNIX socket):
  * the server comes up under securevault._disable_network()'s socket lockdown
    (Linux: AF_UNIX allowed, AF_INET still dead - asserted here);
  * a caller with the issued token completes the HMAC handshake and gets a
    reply; a caller with the WRONG token gets nothing but a refusal, and the
    server keeps serving afterwards (fail-closed, no wedge);
  * on Linux the socket dir is 0700, the socket and token are 0600, all inside
    $XDG_RUNTIME_DIR (or the per-uid fallback);
  * stopping the server (= locking/closing the vault) tears the endpoint down
    and calls fail with "not open/unlocked" - lock severs the bridge;
  * svhost.py speaks the native-messaging framing on stdio and relays to the
    server: ping round-trips, unknown ops are refused in the host itself.

    python selftest_ipc.py       (run from the src/ folder)
"""

import os, sys, json, stat, struct, subprocess, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# scratch address BEFORE svipc import (it binds ADDRESS/TOKEN_PATH at import)
_tmp = tempfile.mkdtemp(prefix="svipc-test-")
if os.name == "nt":
    ADDR = r"\\.\pipe\SecureVault.selftest." + str(os.getpid())
else:
    ADDR = os.path.join(_tmp, "rt", "autofill.sock")
os.environ["SECUREVAULT_PIPE"] = ADDR

import securevault  # noqa: applies _disable_network() - the point of the test
import svipc

fails = 0


def check(cond, msg):
    global fails
    print(("PASS" if cond else "FAIL"), msg)
    if not cond:
        fails += 1


# ---------------------------------------------------------------- socket lockdown
import socket
if os.name != "nt":
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        check(False, "AF_INET is blocked")
    except OSError:
        check(True, "AF_INET is blocked (network stays disabled)")
    try:
        socket.create_connection(("127.0.0.1", 9))
        check(False, "create_connection is blocked")
    except OSError:
        check(True, "create_connection is blocked")

# ------------------------------------------------------------------- fake vault
CALLS = []

def fake_vault_handler(req):
    """Stands in for AutofillService._handle: records what arrived and answers
    ping only - transport must not care what the vault says."""
    CALLS.append(req)
    if req.get("op") == "ping":
        return {"ok": True, "serving": True, "paired": 0}
    return {"ok": False, "error": "fake vault refuses", "code": "denied"}


token = svipc.issue_token()
check(bool(token) and len(token) == 64, "token issued (32 random bytes, hex)")

srv = svipc.PipeServer(fake_vault_handler, token)
srv.start()
deadline = time.monotonic() + 5
while time.monotonic() < deadline and not svipc._pipe_ready(100):
    time.sleep(0.05)

r = svipc.call({"op": "ping"}, timeout_ms=3000)
check(r.get("ok") is True and r.get("serving") is True,
      "ping round-trips through the server with the issued token")

# ------------------------------------------------------------------ permissions
if os.name != "nt":
    d = os.path.dirname(ADDR)
    check(stat.S_IMODE(os.lstat(d).st_mode) == 0o700, "socket dir is 0700")
    check(stat.S_IMODE(os.lstat(ADDR).st_mode) == 0o600, "socket is 0600")
    check(stat.S_IMODE(os.lstat(svipc.TOKEN_PATH).st_mode) == 0o600,
          "token file is 0600")
    check(os.path.dirname(svipc.TOKEN_PATH) == d,
          "token lives in the same private runtime dir")

# --------------------------------------------------------------- wrong token
good = svipc.read_token()
with open(svipc.TOKEN_PATH, "w") as f:        # what a caller without the real
    f.write("0" * 64)                          # token would present
r = svipc.call({"op": "ping"}, timeout_ms=1200)
check(not r.get("ok"), "wrong token: handshake fails, no reply escapes")
with open(svipc.TOKEN_PATH, "w") as f:
    f.write(good)
if os.name != "nt":
    os.chmod(svipc.TOKEN_PATH, 0o600)
r = svipc.call({"op": "ping"}, timeout_ms=3000)
check(r.get("ok") is True, "server still serves the real token afterwards "
                           "(a bad handshake cannot wedge it)")

# ----------------------------------------------------------------- svhost relay
def frame(obj):
    data = json.dumps(obj).encode("utf-8")
    return struct.pack("<I", len(data)) + data

def unframe_all(buf):
    out = []
    while len(buf) >= 4:
        (n,) = struct.unpack("<I", buf[:4])
        if len(buf) < 4 + n:
            break
        out.append(json.loads(buf[4:4 + n].decode("utf-8")))
        buf = buf[4 + n:]
    return out

env = dict(os.environ, SECUREVAULT_PIPE=ADDR)
p = subprocess.run(
    [sys.executable, os.path.join(HERE, "svhost.py"),
     "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"],
    input=frame({"op": "ping"}) + frame({"op": "shutdown-the-machine"}),
    capture_output=True, timeout=30, env=env)
replies = unframe_all(p.stdout)
check(len(replies) == 2, "svhost answered both framed messages on stdout")
check(replies and replies[0].get("ok") is True,
      "svhost relayed ping to the fake vault and back")
check(len(replies) > 1 and not replies[1].get("ok")
      and "unsupported op" in replies[1].get("error", ""),
      "svhost refuses an op outside the relay whitelist itself")
check(all(c.get("op") == "ping" for c in CALLS),
      "the refused op never reached the vault side")
check(any(c.get("caller") == "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
          for c in CALLS), "svhost attached the caller origin for the vault to log")

# --------------------------------------------------------- lock tears it down
srv.stop()
srv.join(timeout=5)
svipc.clear_token()
if os.name != "nt":
    check(not os.path.exists(ADDR), "stopping the server removes the socket")
check(not os.path.exists(svipc.TOKEN_PATH), "clear_token removes the token")
r = svipc.call({"op": "ping"}, timeout_ms=600)
check(not r.get("ok") and "not open/unlocked" in r.get("error", ""),
      "after stop (= lock/close), calls fail closed with 'not open/unlocked'")

# --------------------------------------------------- socketpair carve-out
# GLib's Python bindings need socketpair() for signal wakeup; blocking it
# killed the tray's event loop (field defect). AF_UNIX pairs must work,
# anything routable must not.
if os.name != "nt":
    a, b = socket.socketpair()
    a.close(); b.close()
    check(True, "AF_UNIX socketpair works (GLib main loops can run)")
    try:
        socket.socketpair(socket.AF_INET)
        check(False, "non-UNIX socketpair blocked")
    except OSError:
        check(True, "non-UNIX socketpair blocked")

# ------------------------------------------------ single-instance activation
svipc.ACTIVATE_ADDRESS = (ADDR + ".act") if os.name != "nt" else \
    (svipc.ACTIVATE_ADDRESS + f".test{os.getpid()}")
hits = []
act = svipc.ActivationServer(lambda: hits.append(1))
act.start()
deadline = time.monotonic() + 5
while time.monotonic() < deadline and not os.path.exists(svipc.ACTIVATE_ADDRESS) \
        and os.name != "nt":
    time.sleep(0.05)
check(svipc.activate_running(), "activation poke reaches a running instance")
time.sleep(0.3)
check(len(hits) >= 1, "on_activate fired ('show yourself')")
act.stop()
act.join(timeout=5)
check(not svipc.activate_running(timeout_ms=400),
      "no instance -> activate_running is False (fresh launch proceeds)")

import shutil
shutil.rmtree(_tmp, ignore_errors=True)
print("\n" + ("ALL PASS" if not fails else f"{fails} FAILED"))
sys.exit(1 if fails else 0)
