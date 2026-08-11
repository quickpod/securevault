#!/usr/bin/env python3
r"""
svsec - best-effort keystroke-logging / monitoring checks for SecureVault.

IMPORTANT / HONEST SCOPE
No userspace program can reliably detect a well-written keylogger, especially a
kernel-mode or hardware one. This module raises the bar with heuristics only:

  1. scans running processes for names/signatures of known keylogging &
     remote-monitoring tools;
  2. flags userspace global-hook helper libraries if present in the process.

Because detection can never be guaranteed, SecureVault's REAL defence is the
on-screen randomized keyboard (see svgui.VirtualKeyboard): the master password
is entered with mouse clicks on shuffled keys, so nothing is typed on the
physical keyboard for a hook or hardware logger to capture.

Everything here is local and read-only; no network (SecureVault disables sockets).
"""
import sys

# Substrings (lower-case) of process image names associated with keyloggers or
# remote monitoring/spyware suites. Presence is a WARNING, not proof.
SUSPECT = [
    "keylog", "kidlogger", "actualkeylogger", "refog", "spyrix", "ardamax",
    "wolfeye", "elite keylogger", "revealer", "hoverwatch", "spytech",
    "realtime-spy", "perfectkeylogger", "blackbox", "flexispy", "mspy",
    "spyagent", "imonitor", "netbull", "snoopza", "kgb", "winspy",
    "allinone keylogger", "micro keylogger", "free keylogger", "shadow",
    "veriato", "teramind", "activtrak", "hubstaff", "workpuls", "spyrix",
    "pcspy", "keystroke", "logkeys", "nanny",
]

def _iter_process_names():
    """Yield running process image names. Uses Windows Toolhelp via ctypes so it
    works inside the frozen exe with no third-party dependency."""
    if not sys.platform.startswith("win"):
        try:
            import psutil  # optional on non-Windows
            for p in psutil.process_iter(["name"]):
                yield (p.info.get("name") or "")
        except Exception:
            return
        return
    import ctypes
    from ctypes import wintypes
    TH32CS_SNAPPROCESS = 0x00000002
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_char * 260)]

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return
    try:
        entry = PROCESSENTRY32(); entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        ok = k32.Process32First(snap, ctypes.byref(entry))
        while ok:
            try:
                yield entry.szExeFile.decode("latin-1", "replace")
            except Exception:
                pass
            ok = k32.Process32Next(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)

def _hook_libs_loaded():
    """Userspace keyboard-hook helper libs present in THIS process would be a
    red flag (SecureVault itself imports none)."""
    flags = []
    for mod in ("pynput", "keyboard", "pyxhook", "pyHook"):
        if mod in sys.modules:
            flags.append(f"input-hook library loaded in-process: {mod}")
    return flags

def scan():
    """Return a list of human-readable warning strings (empty => nothing flagged)."""
    warnings = []
    seen = set()
    for name in _iter_process_names():
        low = name.lower()
        for sig in SUSPECT:
            if sig in low and name not in seen:
                seen.add(name)
                warnings.append(f"suspicious process running: {name}")
    warnings.extend(_hook_libs_loaded())
    return warnings

if __name__ == "__main__":
    w = scan()
    if not w:
        print("no known keylogger signatures found (heuristic scan only).")
    else:
        print("WARNINGS:")
        for x in w:
            print("  -", x)
