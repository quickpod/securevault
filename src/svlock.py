#!/usr/bin/env python3
r"""
svlock - SYSTEM-level auto-lock triggers for SecureVault.

Field lesson (owner's Quick OS laptop, 1.0.8): the old auto-lock timer counted
only VAULT/AUTOFILL interaction as activity, so a user hard at work in other
apps looked "idle" to it and the vault locked mid-work. The reworked model:

  PRIMARY  - lock the vault when the DESKTOP locks / the screensaver starts /
             the machine is about to sleep. If the user isn't at the desk (or
             the machine suspends), the vault must not stay open; while they
             ARE at the desk, the vault never locks under them.
  FALLBACK - a timer measured against TRUE SYSTEM INPUT IDLE (keyboard/mouse
             anywhere on the machine), not app interaction.

This module supplies both primitives; svgui owns the policy (config checks,
what "lock" means). Desktop UNLOCK is deliberately not observed - unlocking
the desktop must never unlock the vault.

  Monitor  - watches for desktop lock / suspend and reports events:
               Linux    session bus  org.freedesktop.ScreenSaver
                                     ActiveChanged(true)   (Plasma emits on
                                     manual lock, idle-lock and lid close)
                        system bus   org.freedesktop.login1.Session Lock
                                     (loginctl lock-session and friends)
                                     org.freedesktop.login1.Manager
                                     PrepareForSleep(true) (suspend/hibernate)
                        All three are cheap to watch, so all three are watched;
                        duplicates are harmless (locking is idempotent and the
                        first event tears the session down). The GLib main
                        loop runs on its OWN thread-default context on a
                        daemon thread, so it neither needs nor disturbs
                        pystray's loop, and works when the tray is absent.
               Windows  a hidden message window on a daemon thread:
                        WTSRegisterSessionNotification ->
                        WM_WTSSESSION_CHANGE (WTS_SESSION_LOCK), plus
                        WM_POWERBROADCAST (PBT_APMSUSPEND). The message ->
                        event mapping is the pure function decide_win_event(),
                        unit-tested without a real message pump.
  idle_ms  - milliseconds since the LAST keyboard/mouse input system-wide:
               Linux    XScreenSaverQueryInfo (X11 - Quick OS sessions are
                        X11); falls back to the session bus
                        GetSessionIdleTime when XSS is unavailable
               Windows  GetLastInputInfo
             Returns None when no source works; callers must treat None as
             "unknown", never as "idle".

Events are delivered on the MONITOR's thread. Callers marshal them (svgui
pushes them onto a queue drained by the Tk loop). Everything degrades quietly:
a machine with no DBus/X11 still runs the app, it just has fewer triggers.

Nothing here touches the network: DBus rides the session/system AF_UNIX bus
sockets inside libgio (C-level, same class of machine-local IPC as svipc's
carve-out), and the X11/Win32 calls are local library calls.
"""

import os
import threading

IS_WINDOWS = os.name == "nt"

# event names delivered to Monitor's callback
EVENT_DESKTOP_LOCK = "desktop-lock"
EVENT_SUSPEND = "suspend"

# ---------------------------------------------------------------- Windows
# constants + pure decision function (unit-tested; the message pump just
# feeds real messages through the same path)
WM_WTSSESSION_CHANGE = 0x02B1
WTS_SESSION_LOCK = 0x0007
WM_POWERBROADCAST = 0x0218
PBT_APMSUSPEND = 0x0004


def decide_win_event(msg, wparam):
    """Map a Win32 message to an svlock event name (or None).

    Only WTS_SESSION_LOCK maps to a lock - WTS_SESSION_UNLOCK and the rest of
    the WTS family deliberately map to nothing (desktop unlock must never
    touch the vault), and only PBT_APMSUSPEND maps to suspend (resume events
    grant nothing)."""
    if msg == WM_WTSSESSION_CHANGE and wparam == WTS_SESSION_LOCK:
        return EVENT_DESKTOP_LOCK
    if msg == WM_POWERBROADCAST and wparam == PBT_APMSUSPEND:
        return EVENT_SUSPEND
    return None


def decide_dbus_event(interface, member, arg0):
    """Map a DBus signal to an svlock event name (or None). Pure + unit-tested.

    arg0 is the signal's first argument where it has one (the boolean of
    ActiveChanged / PrepareForSleep); Lock has none. ActiveChanged(false) and
    PrepareForSleep(false) (resume) map to nothing by design."""
    if interface == "org.freedesktop.ScreenSaver" and member == "ActiveChanged":
        return EVENT_DESKTOP_LOCK if bool(arg0) else None
    if interface == "org.freedesktop.login1.Session" and member == "Lock":
        return EVENT_DESKTOP_LOCK
    if interface == "org.freedesktop.login1.Manager" and member == "PrepareForSleep":
        return EVENT_SUSPEND if bool(arg0) else None
    return None


def idle_exceeded(idle, minutes):
    """True when a KNOWN idle time (ms) has reached the threshold (minutes).
    None idle (source unavailable) is never 'exceeded' - the caller decides
    what its fallback is. minutes <= 0 means the idle lock is off."""
    if idle is None or minutes is None or minutes <= 0:
        return False
    return idle >= minutes * 60_000


# ------------------------------------------------------------------ Monitor
class Monitor:
    """Watch for desktop-lock/suspend; call ``on_event(name)`` from a daemon
    thread. start() returns True when at least one trigger source is live -
    callers may surface a warning when it is False. stop() is idempotent."""

    def __init__(self, on_event):
        self.on_event = on_event
        self._impl = None

    def start(self):
        if self._impl is not None:
            return True
        impl = (_WindowsMonitor(self.on_event) if IS_WINDOWS
                else _LinuxMonitor(self.on_event))
        try:
            if impl.start():
                self._impl = impl
                return True
        except Exception:
            pass
        return False

    def active(self):
        return self._impl is not None

    def stop(self):
        impl, self._impl = self._impl, None
        if impl is not None:
            try:
                impl.stop()
            except Exception:
                pass


class _LinuxMonitor:
    """GLib/Gio DBus signal watcher on a private main context + daemon thread."""

    def __init__(self, on_event):
        self.on_event = on_event
        self._loop = None
        self._subs = []                    # [(connection, subscription_id)]
        self._thread = None

    def _dispatch(self, interface, member, arg0):
        evt = decide_dbus_event(interface, member, arg0)
        if evt is not None:
            try:
                self.on_event(evt)
            except Exception:
                pass

    def start(self):
        try:
            import gi
            gi.require_version("GLib", "2.0")
            gi.require_version("Gio", "2.0")
            from gi.repository import GLib, Gio
        except Exception:
            return False

        ready = threading.Event()
        state = {"ok": False}

        def _on_signal(_conn, _sender, _path, iface, member, params):
            arg0 = None
            try:
                up = params.unpack()
                if up:
                    arg0 = up[0]
            except Exception:
                pass
            self._dispatch(iface, member, arg0)

        def run():
            try:
                ctx = GLib.MainContext()
                ctx.push_thread_default()   # subscriptions dispatch HERE
                subs = []
                try:
                    session = Gio.bus_get_sync(Gio.BusType.SESSION, None)
                    subs.append((session, session.signal_subscribe(
                        None, "org.freedesktop.ScreenSaver", "ActiveChanged",
                        None, None, Gio.DBusSignalFlags.NONE, _on_signal)))
                except Exception:
                    pass
                try:
                    system = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
                    subs.append((system, system.signal_subscribe(
                        "org.freedesktop.login1",
                        "org.freedesktop.login1.Session", "Lock",
                        None, None, Gio.DBusSignalFlags.NONE, _on_signal)))
                    subs.append((system, system.signal_subscribe(
                        "org.freedesktop.login1",
                        "org.freedesktop.login1.Manager", "PrepareForSleep",
                        "/org/freedesktop/login1", None,
                        Gio.DBusSignalFlags.NONE, _on_signal)))
                except Exception:
                    pass
                self._subs = subs
                if not subs:
                    return
                self._loop = GLib.MainLoop(ctx)
                state["ok"] = True
            finally:
                ready.set()
            self._loop.run()               # until stop()
            for conn, sid in self._subs:
                try:
                    conn.signal_unsubscribe(sid)
                except Exception:
                    pass
            self._subs = []

        self._thread = threading.Thread(target=run, daemon=True,
                                        name="SecureVault-LockMonitor")
        self._thread.start()
        ready.wait(timeout=10)
        return state["ok"]

    def stop(self):
        loop = self._loop
        self._loop = None
        if loop is not None:
            try:
                loop.quit()                # thread-safe; wakes the context
            except Exception:
                pass


class _WindowsMonitor:
    """Hidden (never shown, NOT message-only: WM_POWERBROADCAST is a broadcast
    and message-only windows do not receive broadcasts) top-level window +
    message pump on a daemon thread. Session-change messages arrive via
    WTSRegisterSessionNotification; every message runs through
    decide_win_event(), the same pure function the unit tests exercise."""

    _CLASS = "SecureVaultLockMonitor"

    def __init__(self, on_event):
        self.on_event = on_event
        self._hwnd = None
        self._thread = None
        self._wndproc = None               # keep the callback alive

    def start(self):
        if not IS_WINDOWS:
            return False
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        wtsapi32 = ctypes.windll.wtsapi32
        kernel32 = ctypes.windll.kernel32

        WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_longlong, wintypes.HWND,
                                     wintypes.UINT, wintypes.WPARAM,
                                     wintypes.LPARAM)

        class WNDCLASS(ctypes.Structure):
            _fields_ = [("style", wintypes.UINT),
                        ("lpfnWndProc", WNDPROC),
                        ("cbClsExtra", ctypes.c_int),
                        ("cbWndExtra", ctypes.c_int),
                        ("hInstance", wintypes.HINSTANCE),
                        ("hIcon", wintypes.HICON),
                        ("hCursor", ctypes.c_void_p),
                        ("hbrBackground", wintypes.HBRUSH),
                        ("lpszMenuName", wintypes.LPCWSTR),
                        ("lpszClassName", wintypes.LPCWSTR)]

        WM_DESTROY = 0x0002

        def _proc(hwnd, msg, wparam, lparam):
            if msg == WM_DESTROY:
                try:
                    wtsapi32.WTSUnRegisterSessionNotification(hwnd)
                except Exception:
                    pass
                user32.PostQuitMessage(0)   # ends the GetMessage loop
                return 0
            evt = decide_win_event(msg, wparam)
            if evt is not None:
                try:
                    self.on_event(evt)
                except Exception:
                    pass
                return 1 if msg == WM_POWERBROADCAST else 0
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        ready = threading.Event()
        state = {"ok": False}

        def run():
            try:
                self._wndproc = WNDPROC(_proc)
                wc = WNDCLASS()
                wc.lpfnWndProc = self._wndproc
                wc.hInstance = kernel32.GetModuleHandleW(None)
                wc.lpszClassName = self._CLASS
                user32.RegisterClassW(ctypes.byref(wc))   # dup class = fine
                hwnd = user32.CreateWindowExW(
                    0, self._CLASS, self._CLASS, 0, 0, 0, 0, 0,
                    None, None, wc.hInstance, None)
                if not hwnd:
                    return
                # NOTIFY_FOR_THIS_SESSION = 0
                wtsapi32.WTSRegisterSessionNotification(hwnd, 0)
                self._hwnd = hwnd
                state["ok"] = True
            finally:
                ready.set()
            msg = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
            # WM_CLOSE -> DefWindowProc DestroyWindow -> WM_DESTROY already
            # unregistered the WTS notification and posted the quit.

        self._thread = threading.Thread(target=run, daemon=True,
                                        name="SecureVault-LockMonitor")
        self._thread.start()
        ready.wait(timeout=10)
        return state["ok"]

    def stop(self):
        hwnd, self._hwnd = self._hwnd, None
        if hwnd:
            try:
                import ctypes
                WM_CLOSE = 0x0010
                ctypes.windll.user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            except Exception:
                pass


# ------------------------------------------------------------------ idle
_x11 = {"checked": False, "dpy": None, "xlib": None, "xss": None, "info": None}


def _x11_idle_ms():
    """XScreenSaverQueryInfo idle, in ms. One cached Display connection for
    the process (a fresh XOpenDisplay every 30s tick would leak client slots
    on some servers). Any failure poisons the cache -> None from then on."""
    import ctypes
    import ctypes.util

    if _x11["checked"] and _x11["dpy"] is None:
        return None
    try:
        if not _x11["checked"]:
            _x11["checked"] = True
            xlib_name = ctypes.util.find_library("X11")
            xss_name = ctypes.util.find_library("Xss")
            if not xlib_name or not xss_name:
                return None
            xlib = ctypes.CDLL(xlib_name)
            xss = ctypes.CDLL(xss_name)

            class XScreenSaverInfo(ctypes.Structure):
                _fields_ = [("window", ctypes.c_ulong),
                            ("state", ctypes.c_int),
                            ("kind", ctypes.c_int),
                            ("til_or_since", ctypes.c_ulong),
                            ("idle", ctypes.c_ulong),
                            ("eventMask", ctypes.c_ulong)]

            xlib.XOpenDisplay.restype = ctypes.c_void_p
            xlib.XOpenDisplay.argtypes = [ctypes.c_char_p]
            xlib.XDefaultRootWindow.restype = ctypes.c_ulong
            xlib.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
            xss.XScreenSaverAllocInfo.restype = ctypes.POINTER(XScreenSaverInfo)
            xss.XScreenSaverQueryExtension.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int)]
            xss.XScreenSaverQueryInfo.argtypes = [
                ctypes.c_void_p, ctypes.c_ulong,
                ctypes.POINTER(XScreenSaverInfo)]
            dpy = xlib.XOpenDisplay(None)
            if not dpy:
                return None
            ev, err = ctypes.c_int(0), ctypes.c_int(0)
            if not xss.XScreenSaverQueryExtension(dpy, ctypes.byref(ev),
                                                  ctypes.byref(err)):
                xlib.XCloseDisplay(dpy)
                return None
            _x11.update(dpy=dpy, xlib=xlib, xss=xss,
                        info=xss.XScreenSaverAllocInfo())
        dpy, xlib, xss, info = (_x11["dpy"], _x11["xlib"], _x11["xss"],
                                _x11["info"])
        if dpy is None:
            return None
        if not xss.XScreenSaverQueryInfo(dpy, xlib.XDefaultRootWindow(dpy),
                                         info):
            return None
        return int(info.contents.idle)
    except Exception:
        _x11["dpy"] = None                 # poison: don't retry every tick
        return None


def _dbus_idle_ms():
    """Fallback: org.freedesktop.ScreenSaver.GetSessionIdleTime (SECONDS per
    the fd.o spec - KDE implements it) over a one-shot sync call."""
    try:
        import gi
        gi.require_version("Gio", "2.0")
        from gi.repository import Gio, GLib
        bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        res = bus.call_sync(
            "org.freedesktop.ScreenSaver", "/org/freedesktop/ScreenSaver",
            "org.freedesktop.ScreenSaver", "GetSessionIdleTime", None,
            GLib.VariantType("(u)"), Gio.DBusCallFlags.NONE, 2000, None)
        return int(res.unpack()[0]) * 1000
    except Exception:
        return None


def _win_idle_ms():
    """GetLastInputInfo: ms since the last keyboard/mouse input, any app.
    Unsigned 32-bit tick arithmetic (wraps at ~49.7 days)."""
    try:
        import ctypes
        from ctypes import wintypes

        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]

        lii = LASTINPUTINFO()
        lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
            return None
        now = ctypes.windll.kernel32.GetTickCount()
        return (now - lii.dwTime) & 0xFFFFFFFF
    except Exception:
        return None


def idle_ms():
    """Milliseconds since the last SYSTEM-WIDE keyboard/mouse input, or None
    when no source is available (callers: None = unknown, NOT idle)."""
    if IS_WINDOWS:
        return _win_idle_ms()
    v = _x11_idle_ms()
    if v is not None:
        return v
    return _dbus_idle_ms()
