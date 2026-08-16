#!/usr/bin/env python3
r"""
SecureVault - the "open outside the vault" workspace.

Decrypts a stored file into a private scratch directory, hands it to whatever
Windows application owns that file type, watches for that application to close,
lets the GUI offer to save any edits back into the vault, then overwrites and
deletes the plaintext.

Scratch files live in one per-session directory under %LOCALAPPDATA%\Temp whose
ACL is reset to the current user only. It is wiped when the vault window closes,
and again from an atexit hook if the process dies some other way.

This is the one place SecureVault writes plaintext to disk on purpose - see
"Honest limitations" in the README.

Detecting "the app closed" is best-effort, and there are three outcomes:
  handle  - ShellExecuteEx gave us a process handle; we wait on it. Exact.
  lock    - no handle (the file went to an already-running instance), but the
            app took an exclusive lock; we treat releasing it as the close.
  manual  - neither signal appeared within LOCK_GRACE seconds. The file stays
            until the user says they are done, or the vault window closes.
Nothing is ever wiped on a timer, so a slow read is never mistaken for a close.
"""
import atexit, hashlib, os, re, shutil, subprocess, tempfile, threading, time

IS_WINDOWS = os.name == "nt"

WATCH_POLL   = 1.0      # seconds between lock checks
LOCK_GRACE   = 20.0     # how long to wait for an app to take a lock before
                        # giving up on auto-detection and falling back to manual
WIPE_CHUNK   = 1 << 20

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _shell32  = ctypes.WinDLL("shell32", use_last_error=True)
    _shlwapi  = ctypes.WinDLL("shlwapi", use_last_error=True)

    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    SEE_MASK_FLAG_NO_UI     = 0x00000400
    SW_SHOWNORMAL           = 1

    # deliberately NOT using SEE_MASK_NOASYNC: it makes ShellExecuteEx wait for
    # the shell/DDE conversation to finish, which hangs the caller on anything
    # modal. We launch from the UI thread, which outlives the call, so the flag
    # buys nothing and costs a freeze.

    ASSOCF_INIT_IGNOREUNKNOWN = 0x00000400
    ASSOCSTR_EXECUTABLE       = 2

    GENERIC_READ            = 0x80000000
    OPEN_EXISTING           = 3
    ERROR_SHARING_VIOLATION = 32
    ERROR_LOCK_VIOLATION    = 33
    WAIT_OBJECT_0           = 0
    _INVALID_HANDLE         = ctypes.c_void_p(-1).value

    class _SHELLEXECUTEINFOW(ctypes.Structure):
        # hIcon/hMonitor are a union; both are pointer-sized, so one field does.
        _fields_ = [("cbSize",       wintypes.DWORD),
                    ("fMask",        ctypes.c_ulong),
                    ("hwnd",         wintypes.HWND),
                    ("lpVerb",       wintypes.LPCWSTR),
                    ("lpFile",       wintypes.LPCWSTR),
                    ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory",  wintypes.LPCWSTR),
                    ("nShow",        ctypes.c_int),
                    ("hInstApp",     wintypes.HANDLE),
                    ("lpIDList",     ctypes.c_void_p),
                    ("lpClass",      wintypes.LPCWSTR),
                    ("hkeyClass",    wintypes.HANDLE),
                    ("dwHotKey",     wintypes.DWORD),
                    ("hIcon",        wintypes.HANDLE),
                    ("hProcess",     wintypes.HANDLE)]

    _shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_SHELLEXECUTEINFOW)]
    _shell32.ShellExecuteExW.restype  = wintypes.BOOL
    _kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                      ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                      wintypes.HANDLE]
    _kernel32.CreateFileW.restype  = wintypes.HANDLE
    _kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _kernel32.WaitForSingleObject.restype  = wintypes.DWORD
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _shlwapi.AssocQueryStringW.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR,
                                           wintypes.LPCWSTR, wintypes.LPWSTR,
                                           ctypes.POINTER(wintypes.DWORD)]
    _shlwapi.AssocQueryStringW.restype  = ctypes.c_long


class OpenError(Exception):
    pass


# --------------------------------------------------------------- win32 helpers
def has_association(path):
    r"""True if Windows has a real handler for this extension.

    ASSOCF_INIT_IGNOREUNKNOWN is the point of this call: without it every
    unknown extension "resolves" to OpenWith.exe and looks associated."""
    if not IS_WINDOWS:
        return True
    ext = os.path.splitext(path)[1]
    if not ext:
        return False
    buf = ctypes.create_unicode_buffer(1024)
    n = wintypes.DWORD(len(buf))
    hr = _shlwapi.AssocQueryStringW(ASSOCF_INIT_IGNOREUNKNOWN, ASSOCSTR_EXECUTABLE,
                                    ext, None, buf, ctypes.byref(n))
    if hr != 0:
        return False
    exe = (buf.value or "").strip()
    return bool(exe) and "openwith.exe" not in exe.lower()


def _shell_open(path):
    r"""Launch `path` with its associated application. Returns a process HANDLE
    when Windows gives us one, else None - some apps (Office, browsers) hand the
    file to an already-running instance and the launched stub exits at once.

    The association is checked FIRST and refused if absent. Letting
    ShellExecuteEx handle an unknown type pops the modal "How do you want to
    open this file?" picker, which blocks the calling thread - i.e. freezes the
    vault window - until somebody clicks it. Use open_with() for that case."""
    if not IS_WINDOWS:
        subprocess.Popen(["xdg-open", path])
        return None
    if not has_association(path):
        raise OpenError("no Windows application is associated with this file type")
    info = _SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask  = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI
    info.lpVerb = None                      # default verb = "open"
    info.lpFile = path
    info.lpDirectory = os.path.dirname(path)
    info.nShow  = SW_SHOWNORMAL
    if not _shell32.ShellExecuteExW(ctypes.byref(info)):
        rc = ctypes.get_last_error()
        code = ctypes.cast(info.hInstApp, ctypes.c_void_p).value or 0
        if code == 31:                      # SE_ERR_NOASSOC
            raise OpenError("no Windows application is associated with this file type")
        raise OpenError(f"ShellExecuteEx failed (error {rc or code})")
    return info.hProcess or None


def open_with(path):
    r"""Show Windows' "Open with" picker for a file type we have no handler for.
    Spawned as a separate process so the picker can never block the vault
    window. There is no process handle to watch afterwards, so the caller has to
    treat the file as manually managed."""
    if not IS_WINDOWS:
        subprocess.Popen(["xdg-open", path])
        return None
    subprocess.Popen(["rundll32.exe", "shell32.dll,OpenAs_RunDLL", path],
                     creationflags=0x08000000)
    return None


def _is_locked(path):
    r"""True if another process holds `path` open without sharing. Used only as a
    secondary close signal, and only after we have seen the lock held at least
    once - an app that never locks is never assumed to have finished."""
    if not IS_WINDOWS:
        return False
    h = _kernel32.CreateFileW(path, GENERIC_READ, 0, None, OPEN_EXISTING, 0, None)
    if h == _INVALID_HANDLE or h is None:
        return ctypes.get_last_error() in (ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION)
    _kernel32.CloseHandle(h)
    return False


def _lock_down(path):
    """Reset the scratch directory's ACL to the current user only. It already
    sits inside the user's own profile; this just removes inherited grants."""
    if not IS_WINDOWS:
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
        return
    user = os.environ.get("USERNAME")
    if not user:
        return
    try:
        subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", f"{user}:(OI)(CI)F"],
                       capture_output=True, timeout=15, creationflags=0x08000000)
    except Exception:
        pass                                # non-fatal: the profile ACL still applies


def _secure_delete(path):
    """Overwrite the bytes, then unlink. On an SSD wear-levelling can retain the
    original blocks, so treat this as best effort, not an erasure guarantee."""
    try:
        n = os.path.getsize(path)
        with open(path, "r+b", buffering=0) as f:
            left = n
            while left > 0:
                block = min(WIPE_CHUNK, left)
                f.write(os.urandom(block))
                left -= block
            f.flush()
            os.fsync(f.fileno())
            f.truncate(0)
    except OSError:
        pass
    try:
        os.remove(path)
    except OSError:
        pass


_BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

def _safe_basename(name):
    base = _BAD_CHARS.sub("_", name.split("/")[-1]).strip(" .")
    return base or "file"


# ------------------------------------------------------------------- workspace
class Workspace:
    r"""Owns the scratch directory and every file currently checked out of the
    vault. Staging and wiping are thread-safe; launching should happen on the
    UI thread (ShellExecuteEx wants a COM-initialised caller)."""

    def __init__(self, vault):
        self.vault = vault
        self.dir = None
        self._entries = {}                  # vault name -> entry dict
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._seq = 0
        atexit.register(self.wipe_all)

    # ---- directory
    def _ensure_dir(self):
        with self._lock:
            if self.dir and os.path.isdir(self.dir):
                return self.dir
            # POSIX: prefer $XDG_RUNTIME_DIR - per-user 0700 tmpfs, so staged
            # plaintext lives in RAM and vanishes at logout even if the wipe
            # never runs. Windows (and the no-session fallback) keeps tempdir.
            base = None
            if not IS_WINDOWS:
                rt = os.environ.get("XDG_RUNTIME_DIR")
                if rt and os.path.isdir(rt):
                    base = rt
            self.dir = tempfile.mkdtemp(prefix="securevault-open-", dir=base)
            _lock_down(self.dir)
            return self.dir

    # ---- staging / launching
    def is_open(self, name):
        with self._lock:
            return name in self._entries

    def list_open(self):
        with self._lock:
            return [dict(e) for e in self._entries.values()]

    def stage(self, name):
        """Decrypt `name` to the scratch directory. Slow - call off the UI
        thread. Returns the entry dict; the caller then calls launch()."""
        if self.is_open(name):
            raise OpenError(f"{name} is already open")
        data = self.vault.read_bytes(name)
        root = self._ensure_dir()
        with self._lock:
            self._seq += 1
            sub = os.path.join(root, str(self._seq))
        os.makedirs(sub, exist_ok=True)
        path = os.path.join(sub, _safe_basename(name))
        with open(path, "wb") as f:
            f.write(data)
        entry = {"name": name, "path": path, "subdir": sub,
                 "sha": hashlib.sha256(data).hexdigest(),
                 "handle": None, "state": "staged", "detect": None}
        with self._lock:
            self._entries[name] = entry
        return entry

    def launch(self, entry, on_closed, picker=False):
        """Hand the staged file to its application and start watching it.
        `on_closed(name, detect)` fires from a worker thread - marshal it.
        With picker=True the user chooses the app instead, which gives us no
        process handle, so that file ends up manually managed.

        On failure the entry is left staged: the caller decides whether to retry
        via the picker or discard it (which wipes the plaintext)."""
        entry["handle"] = open_with(entry["path"]) if picker else _shell_open(entry["path"])
        entry["state"] = "open"
        entry["detect"] = "handle" if entry["handle"] else "lock"
        t = threading.Thread(target=self._watch, args=(entry, on_closed), daemon=True)
        t.start()
        return entry

    def _watch(self, entry, on_closed):
        if entry["handle"]:
            while not self._stop.is_set():
                if _kernel32.WaitForSingleObject(entry["handle"], 500) == WAIT_OBJECT_0:
                    break
            h, entry["handle"] = entry["handle"], None
            try:
                _kernel32.CloseHandle(h)
            except Exception:
                pass
        else:
            seen_locked = False
            deadline = time.monotonic() + LOCK_GRACE
            while not self._stop.is_set():
                if _is_locked(entry["path"]):
                    seen_locked = True
                elif seen_locked:
                    break                   # held it, then let go => closed
                elif time.monotonic() > deadline:
                    entry["state"] = "manual"
                    entry["detect"] = "manual"
                    on_closed(entry["name"], "manual")
                    return
                time.sleep(WATCH_POLL)
        if self._stop.is_set():             # shutting down; wipe_all handles it
            return
        entry["state"] = "closed"
        on_closed(entry["name"], entry["detect"])

    # ---- results
    def changed(self, name):
        """True if the file on disk no longer matches what we wrote out."""
        with self._lock:
            entry = self._entries.get(name)
        if not entry:
            return False
        try:
            with open(entry["path"], "rb") as f:
                h = hashlib.sha256()
                for chunk in iter(lambda: f.read(WIPE_CHUNK), b""):
                    h.update(chunk)
            return h.hexdigest() != entry["sha"]
        except OSError:
            return False

    def finish(self, name, save_back=False):
        """Optionally write the edits back into the vault, then wipe the
        plaintext. Slow when saving - call off the UI thread."""
        with self._lock:
            entry = self._entries.pop(name, None)
        if not entry:
            return False
        saved = False
        if save_back:
            with open(entry["path"], "rb") as f:
                data = f.read()
            self.vault.write_bytes(name, data)
            saved = True
        self._destroy(entry)
        return saved

    def discard(self, name):
        with self._lock:
            entry = self._entries.pop(name, None)
        if entry:
            self._destroy(entry)

    def _destroy(self, entry):
        if entry.get("handle"):
            try:
                _kernel32.CloseHandle(entry["handle"])
            except Exception:
                pass
            entry["handle"] = None
        _secure_delete(entry["path"])
        shutil.rmtree(entry["subdir"], ignore_errors=True)

    def wipe_all(self):
        """Wipe every checked-out file and the scratch directory itself. Safe to
        call twice; runs from atexit as well as from the window-close handler."""
        self._stop.set()
        with self._lock:
            entries = list(self._entries.values())
            self._entries.clear()
        for entry in entries:
            try:
                self._destroy(entry)
            except Exception:
                pass
        if self.dir and os.path.isdir(self.dir):
            for dp, _dn, fn in os.walk(self.dir):
                for n in fn:
                    _secure_delete(os.path.join(dp, n))
            shutil.rmtree(self.dir, ignore_errors=True)
        self._stop.clear()
