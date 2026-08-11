#!/usr/bin/env python3
r"""
svipc - local IPC between the browser native-messaging host and the running,
        UNLOCKED SecureVault GUI.

Built on multiprocessing.connection with family 'AF_PIPE' (a Windows named
pipe), NOT a socket - so securevault._disable_network(), which neuters the
socket module at import, does not touch it, and nothing here is reachable off
this machine. An earlier hand-rolled ctypes named-pipe server mis-paired
ConnectNamedPipe with client connections (serving only every other client);
multiprocessing.connection handles all of that correctly and adds an HMAC
challenge/response over `authkey` for free.

TRUST MODEL (per the user's choice: "require the app open + unlocked")
  - The Listener runs INSIDE the unlocked GUI process and only while unlocked.
    Close/lock the app and the pipe is gone -> autofill stops.
  - The GUI is the ONLY process holding the DEK. svhost.py is a keyless relay.
  - authkey = a per-launch token in a user-only file that the host reads. The
    HMAC handshake means a caller without the token cannot even complete a
    connection. Honest limit: against malware running as the SAME user the
    token file is readable, so this is not a same-user boundary; the real
    controls are app-must-be-unlocked, per-origin checks, and GUI save/update
    confirmation. Cross-user and remote access are blocked outright.

Messages are JSON via send_bytes/recv_bytes (NOT .send/.recv, which would
pickle - we never unpickle attacker-influenced data).

  request : {"op": "...", ...}
  ops     : ping | query{origin} | identities | generate{length}
            | save{origin,username,password,url} | update{origin,username,password}
  reply   : {"ok": true, ...} | {"ok": false, "error": "..."}
"""

import os, sys, json, time, ctypes, threading
from multiprocessing.connection import Listener, Client

# Overridable so tests can use a scratch pipe without disturbing a running app.
ADDRESS = os.environ.get("SECUREVAULT_PIPE", r"\\.\pipe\SecureVault.autofill")


def _pipe_ready(timeout_ms) -> bool:
    """True if a pipe instance is available within timeout. Guards Client(),
    which on AF_PIPE otherwise blocks indefinitely when NO server exists -
    WaitNamedPipe returns 0 immediately (ERROR_FILE_NOT_FOUND) in that case."""
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.kernel32.WaitNamedPipeW(ADDRESS, int(timeout_ms)))
    except Exception:
        return False
TOKEN_PATH = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                          "SecureVault", "autofill.token")


# ------------------------------------------------------------------ token
def issue_token() -> str:
    import secrets
    os.makedirs(os.path.dirname(TOKEN_PATH), exist_ok=True)
    tok = secrets.token_hex(32)
    with open(TOKEN_PATH, "w", encoding="utf-8") as f:
        f.write(tok)
    try:
        user = os.environ.get("USERNAME", "")
        if user:
            os.system(f'icacls "{TOKEN_PATH}" /inheritance:r /grant:r "{user}:F" >nul 2>&1')
    except Exception:
        pass
    return tok


def read_token() -> str:
    try:
        with open(TOKEN_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def clear_token():
    try:
        os.remove(TOKEN_PATH)
    except OSError:
        pass


# ------------------------------------------------------------------ server
class PipeServer(threading.Thread):
    """Runs inside the unlocked GUI. `handler(request_dict) -> reply_dict` is
    called for each authenticated request. Serves one client at a time, which
    is ample for occasional autofill calls."""
    daemon = True

    def __init__(self, handler, token):
        super().__init__(name="SecureVault-PipeServer")
        self.handler = handler
        self.authkey = token.encode("utf-8")
        self._stop = threading.Event()
        self._listener = None

    def stop(self):
        self._stop.set()
        # unblock a parked accept() by connecting once ourselves
        try:
            c = Client(ADDRESS, family="AF_PIPE", authkey=self.authkey)
            c.close()
        except Exception:
            pass

    def run(self):
        try:
            self._listener = Listener(ADDRESS, family="AF_PIPE", authkey=self.authkey)
        except Exception:
            return
        try:
            while not self._stop.is_set():
                try:
                    conn = self._listener.accept()     # HMAC handshake happens here
                except Exception:
                    if self._stop.is_set():
                        break
                    continue                            # bad authkey etc. - ignore, keep serving
                if self._stop.is_set():
                    try: conn.close()
                    except Exception: pass
                    break
                try:
                    req = json.loads(conn.recv_bytes())
                    try:
                        reply = self.handler(req)
                    except Exception as ex:
                        reply = {"ok": False, "error": str(ex)}
                    conn.send_bytes(json.dumps(reply).encode("utf-8"))
                except Exception:
                    pass
                finally:
                    try: conn.close()
                    except Exception: pass
        finally:
            try: self._listener.close()
            except Exception: pass


# ------------------------------------------------------------------ client
def call(request: dict, timeout_ms=4000) -> dict:
    """One request/reply from the relay side (svhost). The token is the HMAC
    authkey, so it is never placed in the message body."""
    if os.name != "nt":
        return {"ok": False, "error": "windows only"}
    tok = read_token()
    if not tok:
        return {"ok": False, "error": "SecureVault is not open/unlocked"}
    authkey = tok.encode("utf-8")
    deadline = time.monotonic() + timeout_ms / 1000.0
    while time.monotonic() < deadline:
        if not _pipe_ready(200):        # no server (or momentarily busy)
            time.sleep(0.02)
            continue
        try:
            conn = Client(ADDRESS, family="AF_PIPE", authkey=authkey)
        except Exception:
            time.sleep(0.03)                            # busy / between clients / not up yet
            continue
        try:
            conn.send_bytes(json.dumps(request).encode("utf-8"))
            return json.loads(conn.recv_bytes())
        except Exception as ex:
            return {"ok": False, "error": str(ex)}
        finally:
            try: conn.close()
            except Exception: pass
    return {"ok": False, "error": "SecureVault is not open/unlocked"}


def is_serving() -> bool:
    if os.name != "nt":
        return False
    return bool(call({"op": "ping"}, timeout_ms=800).get("ok"))
