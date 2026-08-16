#!/usr/bin/env python3
r"""
selftest_lock - the reworked (1.0.9) auto-lock triggers, hermetically. No Tk,
no DBus daemon, no Windows message pump: the pure decision functions ARE the
logic the live watchers feed, so the tests exercise exactly what ships.

What it proves:
  * decide_win_event: WTS_SESSION_LOCK locks, PBT_APMSUSPEND sleeps, and -
    critically - WTS_SESSION_UNLOCK / PBT_APMRESUME* / random messages map to
    NOTHING (desktop unlock must never touch the vault);
  * decide_dbus_event: ScreenSaver ActiveChanged(true), login1 Session Lock
    and PrepareForSleep(true) trigger; ActiveChanged(false) / Unlock /
    PrepareForSleep(false) (resume) do not;
  * idle_exceeded: threshold math, 'never' (0) and the None = UNKNOWN rule
    (an unreadable idle source must never count as idle);
  * a Monitor wired to a recording callback dispatches through the same
    functions (the Linux watcher's _dispatch path, driven directly);
  * svconfig: new defaults (desktop-lock ON, 30 min idle), migration from the
    pre-1.0.9 'autolock_minutes' (custom value kept, old default 15 becomes
    the new default 30 - system-input idle is a much stricter clock), the
    0 = never round-trip, and clamping;
  * Monitor.stop() is safe before/without/after start.

    python selftest_lock.py       (run from the src/ folder)
"""

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# private config dir BEFORE svconfig import - never the user's real one
os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="svlock-test-")
os.environ.pop("LOCALAPPDATA", None) if os.name != "nt" else None

import svlock
import svconfig

fails = 0


def check(name, ok, detail=""):
    global fails
    print(("  ok    " if ok else "  FAIL  ") + name + (f"  {detail}" if detail and not ok else ""))
    if not ok:
        fails += 1


print("== decide_win_event ==")
E = svlock
check("WTS_SESSION_LOCK -> desktop-lock",
      E.decide_win_event(E.WM_WTSSESSION_CHANGE, E.WTS_SESSION_LOCK) == E.EVENT_DESKTOP_LOCK)
check("WTS_SESSION_UNLOCK -> nothing (unlock never touches the vault)",
      E.decide_win_event(E.WM_WTSSESSION_CHANGE, 0x0008) is None)
check("other WTS members -> nothing",
      all(E.decide_win_event(E.WM_WTSSESSION_CHANGE, w) is None
          for w in (0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x8, 0x9, 0xA, 0xB)))
check("PBT_APMSUSPEND -> suspend",
      E.decide_win_event(E.WM_POWERBROADCAST, E.PBT_APMSUSPEND) == E.EVENT_SUSPEND)
check("PBT_APMRESUMEAUTOMATIC/RESUMESUSPEND -> nothing",
      E.decide_win_event(E.WM_POWERBROADCAST, 0x12) is None
      and E.decide_win_event(E.WM_POWERBROADCAST, 0x7) is None)
check("unrelated message -> nothing",
      E.decide_win_event(0x0001, E.WTS_SESSION_LOCK) is None)

print("== decide_dbus_event ==")
check("ScreenSaver ActiveChanged(true) -> desktop-lock",
      E.decide_dbus_event("org.freedesktop.ScreenSaver", "ActiveChanged", True) == E.EVENT_DESKTOP_LOCK)
check("ScreenSaver ActiveChanged(false) -> nothing",
      E.decide_dbus_event("org.freedesktop.ScreenSaver", "ActiveChanged", False) is None)
check("login1 Session Lock -> desktop-lock",
      E.decide_dbus_event("org.freedesktop.login1.Session", "Lock", None) == E.EVENT_DESKTOP_LOCK)
check("login1 Session Unlock -> nothing",
      E.decide_dbus_event("org.freedesktop.login1.Session", "Unlock", None) is None)
check("PrepareForSleep(true) -> suspend",
      E.decide_dbus_event("org.freedesktop.login1.Manager", "PrepareForSleep", True) == E.EVENT_SUSPEND)
check("PrepareForSleep(false) (resume) -> nothing",
      E.decide_dbus_event("org.freedesktop.login1.Manager", "PrepareForSleep", False) is None)
check("unknown interface -> nothing",
      E.decide_dbus_event("org.example.Nope", "Lock", None) is None)

print("== idle_exceeded ==")
check("at threshold", E.idle_exceeded(30 * 60_000, 30) is True)
check("below threshold", E.idle_exceeded(30 * 60_000 - 1, 30) is False)
check("0 = never, however idle", E.idle_exceeded(10**12, 0) is False)
check("negative minutes = never", E.idle_exceeded(10**12, -5) is False)
check("None idle = UNKNOWN, never exceeded", E.idle_exceeded(None, 1) is False)
check("None minutes = never", E.idle_exceeded(10**12, None) is False)

print("== Monitor dispatch (recording callback, no live buses) ==")
got = []
mon = svlock._LinuxMonitor(got.append)
mon._dispatch("org.freedesktop.ScreenSaver", "ActiveChanged", True)
mon._dispatch("org.freedesktop.ScreenSaver", "ActiveChanged", False)
mon._dispatch("org.freedesktop.login1.Session", "Lock", None)
mon._dispatch("org.freedesktop.login1.Manager", "PrepareForSleep", True)
mon._dispatch("org.freedesktop.login1.Manager", "PrepareForSleep", False)
check("watcher dispatch = [lock, lock, suspend]",
      got == [E.EVENT_DESKTOP_LOCK, E.EVENT_DESKTOP_LOCK, E.EVENT_SUSPEND], repr(got))


def boom(_evt):
    raise RuntimeError("callback exploded")


mon2 = svlock._LinuxMonitor(boom)
try:
    mon2._dispatch("org.freedesktop.login1.Session", "Lock", None)
    check("callback exception is contained", True)
except Exception as ex:
    check("callback exception is contained", False, repr(ex))

m = svlock.Monitor(got.append)
m.stop()                                   # never started
check("stop() before start is safe", True)
check("active() False before start", m.active() is False)

print("== svconfig: defaults, migration, never ==")
cfg = svconfig.load()                      # fresh dir -> pure defaults
check("default lock_on_desktop_lock ON", cfg["lock_on_desktop_lock"] is True)
check("default idle 30 min", cfg["idle_lock_minutes"] == svconfig.DEFAULT_IDLE_MIN == 30)

os.makedirs(svconfig.config_dir(), exist_ok=True)


def write_cfg(d):
    with open(svconfig.config_path(), "w", encoding="utf-8") as f:
        json.dump(d, f)


write_cfg({"autolock_minutes": 15})        # the old default
check("old default 15 migrates to 30", svconfig.idle_lock_minutes() == 30)
write_cfg({"autolock_minutes": 45})        # a customised value
check("customised 45 is kept", svconfig.idle_lock_minutes() == 45)
write_cfg({"autolock_minutes": 99999})
check("migrated value is clamped", svconfig.idle_lock_minutes() == svconfig.IDLE_MAX)
write_cfg({"autolock_minutes": "junk"})
check("junk old value -> default", svconfig.idle_lock_minutes() == 30)
write_cfg({})
check("no old value -> default", svconfig.idle_lock_minutes() == 30)
check("desktop-lock survives migration ON", svconfig.lock_on_desktop_lock() is True)

svconfig.set_idle_lock_minutes(0)
check("0 = never round-trips", svconfig.idle_lock_minutes() == 0)
saved = json.load(open(svconfig.config_path(), encoding="utf-8"))
check("legacy key not rewritten", "autolock_minutes" not in saved)
check("migrated key persisted", saved.get("idle_lock_minutes") == 0)
svconfig.set_idle_lock_minutes(7)
check("positive value round-trips", svconfig.idle_lock_minutes() == 7)
svconfig.set_idle_lock_minutes(-3)
check("negative set -> never", svconfig.idle_lock_minutes() == 0)
svconfig.set_lock_on_desktop_lock(False)
check("desktop-lock OFF round-trips", svconfig.lock_on_desktop_lock() is False)
svconfig.set_lock_on_desktop_lock(True)
check("desktop-lock back ON", svconfig.lock_on_desktop_lock() is True)

print("== idle_ms none-safety ==")
v = svlock.idle_ms()
check("idle_ms returns int or None", v is None or (isinstance(v, int) and v >= 0), repr(v))

print()
if fails:
    print(f"selftest_lock: {fails} FAILURE(S)")
    sys.exit(1)
print("selftest_lock: all checks passed")
