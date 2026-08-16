#!/usr/bin/env python3
r"""
svipc - local IPC between the browser native-messaging host and the running,
        UNLOCKED SecureVault GUI.

Built on multiprocessing.connection with a platform-native, machine-local
address family:

  Windows: family 'AF_PIPE' (a named pipe). NOT a socket - so
           securevault._disable_network(), which neuters the socket module at
           import, does not touch it. An earlier hand-rolled ctypes named-pipe
           server mis-paired ConnectNamedPipe with client connections (serving
           only every other client); multiprocessing.connection handles all of
           that correctly and adds an HMAC challenge/response over `authkey`
           for free.
  Linux:   family 'AF_UNIX', a filesystem socket at
           $XDG_RUNTIME_DIR/securevault/autofill.sock. The directory is 0700
           and per-user (tmpfs, gone at logout), the socket is chmod 0600, and
           _disable_network() on POSIX allows exactly the AF_UNIX family and
           nothing else - AF_INET/AF_INET6 stay dead, so nothing here is
           reachable off this machine on either OS. The SAME
           multiprocessing.connection HMAC handshake runs over the socket; a
           connect() without the token never yields a usable connection
           (fail-closed: a failed handshake is dropped and the server keeps
           serving).

TRUST MODEL (per the user's choice: "require the app open + unlocked")
  - The Listener runs INSIDE the unlocked GUI process and only while unlocked.
    Close/lock the app and the pipe/socket is gone -> autofill stops.
  - The GUI is the ONLY process holding the DEK. svhost.py is a keyless relay.
  - authkey = a per-launch token in a user-only (0600) file that the host
    reads. The HMAC handshake means a caller without the token cannot even
    complete a connection. Honest limit: against malware running as the SAME
    user the token file is readable, so this is not a same-user boundary; the
    real controls are app-must-be-unlocked, svauth pairing + per-request
    signatures, and GUI save/update confirmation. Cross-user access is blocked
    by the 0700 dir + 0600 file modes (Linux) / per-profile ACLs (Windows),
    and remote access is blocked outright on both.

Messages are JSON via send_bytes/recv_bytes (NOT .send/.recv, which would
pickle - we never unpickle attacker-influenced data).

  request : {"op": "...", ...}
  ops     : ping | query{origin} | identities | generate{length}
            | save{origin,username,password,url} | update{origin,username,password}
  reply   : {"ok": true, ...} | {"ok": false, "error": "..."}
"""

import os, sys, json, time, ctypes, threading
from multiprocessing.connection import Listener, Client

IS_WINDOWS = os.name == "nt"
FAMILY = "AF_PIPE" if IS_WINDOWS else "AF_UNIX"


def _runtime_dir():
    """Per-user runtime dir for the socket + token (POSIX only). XDG_RUNTIME_DIR
    is tmpfs, mode 0700, owned by the user and cleared at logout - exactly the
    lifetime a pairing transport should have. The fallback (no session manager,
    e.g. an SSH test run) is a per-uid dir under tempdir with the same 0700."""
    base = os.environ.get("XDG_RUNTIME_DIR")
    if base and os.path.isdir(base):
        return os.path.join(base, "securevault")
    import tempfile
    return os.path.join(tempfile.gettempdir(), f"securevault-{os.getuid()}")


def _default_address():
    if IS_WINDOWS:
        return r"\\.\pipe\SecureVault.autofill"
    return os.path.join(_runtime_dir(), "autofill.sock")


# Overridable so tests can use a scratch pipe/socket without disturbing a
# running app.
ADDRESS = os.environ.get("SECUREVAULT_PIPE") or _default_address()

if IS_WINDOWS:
    TOKEN_PATH = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                              "SecureVault", "autofill.token")
else:
    # next to the socket: same 0700 dir, same per-login lifetime
    TOKEN_PATH = os.environ.get("SECUREVAULT_TOKEN") or \
        os.path.join(os.path.dirname(ADDRESS), "autofill.token")


def _ensure_private_dir(path):
    """Create `path` 0700 and refuse to use it unless it really is a private,
    non-symlink directory owned by this user (fail-closed: better no autofill
    than a socket in a directory someone else controls)."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    st = os.lstat(path)
    import stat as _stat
    if not _stat.S_ISDIR(st.st_mode) or _stat.S_ISLNK(st.st_mode):
        raise OSError(f"not a directory: {path}")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise OSError(f"refusing runtime dir owned by uid {st.st_uid}: {path}")
    os.chmod(path, 0o700)
    return path


def _pipe_ready(timeout_ms) -> bool:
    """True if a server appears to exist. On Windows this guards Client(),
    which on AF_PIPE otherwise blocks indefinitely when NO server exists -
    WaitNamedPipe returns 0 immediately (ERROR_FILE_NOT_FOUND) in that case.
    On POSIX a missing socket path means no server (connect would ECONNREFUSED
    on a stale one, which call() treats the same way)."""
    if not IS_WINDOWS:
        return os.path.exists(ADDRESS)
    try:
        return bool(ctypes.windll.kernel32.WaitNamedPipeW(ADDRESS, int(timeout_ms)))
    except Exception:
        return False


# ------------------------------------------------------------------ token
def issue_token() -> str:
    import secrets
    tok = secrets.token_hex(32)
    if IS_WINDOWS:
        os.makedirs(os.path.dirname(TOKEN_PATH), exist_ok=True)
        with open(TOKEN_PATH, "w", encoding="utf-8") as f:
            f.write(tok)
        try:
            user = os.environ.get("USERNAME", "")
            if user:
                os.system(f'icacls "{TOKEN_PATH}" /inheritance:r /grant:r "{user}:F" >nul 2>&1')
        except Exception:
            pass
    else:
        _ensure_private_dir(os.path.dirname(TOKEN_PATH))
        # 0600 from the first byte - never a window where the token is readable
        fd = os.open(TOKEN_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, tok.encode("ascii"))
        finally:
            os.close(fd)
        os.chmod(TOKEN_PATH, 0o600)
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


# ------------------------------------------------------------------ presence
# A tiny NON-SECRET marker (this process's pid) written while the APP is
# running - locked or unlocked. It lets the relay tell the extension apart
# "SecureVault isn't running" from "running but locked", which are different
# instructions to a user. It grants nothing: the socket/token still only exist
# while unlocked.
PRESENCE_PATH = os.path.join(os.path.dirname(TOKEN_PATH), "app.pid")


def presence_write():
    try:
        if IS_WINDOWS:
            os.makedirs(os.path.dirname(PRESENCE_PATH), exist_ok=True)
            with open(PRESENCE_PATH, "w") as f:
                f.write(str(os.getpid()))
        else:
            _ensure_private_dir(os.path.dirname(PRESENCE_PATH))
            fd = os.open(PRESENCE_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, str(os.getpid()).encode("ascii"))
            finally:
                os.close(fd)
    except Exception:
        pass


def presence_clear():
    try:
        os.remove(PRESENCE_PATH)
    except OSError:
        pass


def app_running() -> bool:
    """Best-effort: does the pid in the presence marker still exist? A stale
    marker after a crash reports False via the liveness check."""
    try:
        with open(PRESENCE_PATH) as f:
            pid = int(f.read().strip() or "0")
    except Exception:
        return False
    if pid <= 0:
        return False
    if IS_WINDOWS:
        try:
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            h = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not h:
                return False
            ctypes.windll.kernel32.CloseHandle(h)
            return True
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


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
        self._stopping = threading.Event()
        self._listener = None

    def stop(self):
        self._stopping.set()
        # unblock a parked accept() by connecting once ourselves
        try:
            c = Client(ADDRESS, family=FAMILY, authkey=self.authkey)
            c.close()
        except Exception:
            pass

    def run(self):
        try:
            if not IS_WINDOWS:
                _ensure_private_dir(os.path.dirname(ADDRESS))
                try:
                    os.unlink(ADDRESS)          # a stale socket from a crash
                except OSError:
                    pass
            self._listener = Listener(ADDRESS, family=FAMILY, authkey=self.authkey)
            if not IS_WINDOWS:
                # Belt: the socket itself 0600. Braces: it lives in a 0700 dir,
                # so even the moment between bind and chmod is unreachable by
                # any other user.
                os.chmod(ADDRESS, 0o600)
        except Exception:
            return
        try:
            while not self._stopping.is_set():
                try:
                    conn = self._listener.accept()     # HMAC handshake happens here
                except Exception:
                    if self._stopping.is_set():
                        break
                    continue                            # bad authkey etc. - ignore, keep serving
                if self._stopping.is_set():
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
            try: self._listener.close()        # also unlinks the AF_UNIX socket
            except Exception: pass
            if not IS_WINDOWS:
                try: os.unlink(ADDRESS)
                except OSError: pass


# -------------------------------------------------------------- activation
# Single-instance activation: launching SecureVault while an instance is
# already running (visible, trayed, or locked-in-tray) must RAISE that
# instance, never error or spawn a second one - it is also the guaranteed way
# back to a background vault even if the tray icon is hidden. The channel is
# deliberately dumb: CONNECTING is the whole message ("show yourself"), no
# payload is read, nothing secret crosses it, and showing the window grants
# nothing (unlocking still takes all three factors). Same-user only on Linux
# via the 0700 runtime dir.
ACTIVATE_ADDRESS = (r"\\.\pipe\SecureVault.activate" if IS_WINDOWS
                    else os.path.join(os.path.dirname(_default_address()),
                                      "activate.sock"))


class ActivationServer(threading.Thread):
    """Runs for the app's whole life. `on_activate()` fires on the server
    thread for every connection - marshal it (the callers push onto the tray
    event queue, which the Tk side drains)."""
    daemon = True

    def __init__(self, on_activate):
        super().__init__(name="SecureVault-Activate")
        self.on_activate = on_activate
        self._stopping = threading.Event()
        self._listener = None

    def stop(self):
        self._stopping.set()
        try:
            c = Client(ACTIVATE_ADDRESS, family=FAMILY)
            c.close()
        except Exception:
            pass

    def run(self):
        try:
            if not IS_WINDOWS:
                _ensure_private_dir(os.path.dirname(ACTIVATE_ADDRESS))
                try:
                    os.unlink(ACTIVATE_ADDRESS)
                except OSError:
                    pass
            self._listener = Listener(ACTIVATE_ADDRESS, family=FAMILY)
            if not IS_WINDOWS:
                os.chmod(ACTIVATE_ADDRESS, 0o600)
        except Exception:
            return
        try:
            while not self._stopping.is_set():
                try:
                    conn = self._listener.accept()
                except Exception:
                    if self._stopping.is_set():
                        break
                    continue
                try:
                    conn.close()
                except Exception:
                    pass
                if self._stopping.is_set():
                    break
                try:
                    self.on_activate()
                except Exception:
                    pass
        finally:
            try:
                self._listener.close()
            except Exception:
                pass
            if not IS_WINDOWS:
                try:
                    os.unlink(ACTIVATE_ADDRESS)
                except OSError:
                    pass


def activate_running(timeout_ms=1200) -> bool:
    """True if a running instance accepted the 'show yourself' poke."""
    deadline = time.monotonic() + timeout_ms / 1000.0
    while time.monotonic() < deadline:
        if IS_WINDOWS and not _pipe_ready_at(ACTIVATE_ADDRESS, 200):
            time.sleep(0.05)
            continue
        if not IS_WINDOWS and not os.path.exists(ACTIVATE_ADDRESS):
            return False
        try:
            c = Client(ACTIVATE_ADDRESS, family=FAMILY)
            c.close()
            return True
        except Exception:
            time.sleep(0.05)
    return False


def _pipe_ready_at(address, timeout_ms) -> bool:
    if not IS_WINDOWS:
        return os.path.exists(address)
    try:
        return bool(ctypes.windll.kernel32.WaitNamedPipeW(address, int(timeout_ms)))
    except Exception:
        return False


# ------------------------------------------------------------------ client
def call(request: dict, timeout_ms=4000) -> dict:
    """One request/reply from the relay side (svhost). The token is the HMAC
    authkey, so it is never placed in the message body."""
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
            conn = Client(ADDRESS, family=FAMILY, authkey=authkey)
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
    return bool(call({"op": "ping"}, timeout_ms=800).get("ok"))
