#!/usr/bin/env python3
r"""
svtray - SecureVault's background-mode tray icon.

Closing the vault window can now mean "keep running in the background" - which
is what keeps browser autofill answering while no window is on screen. This
module owns the notification-area icon for that mode:

  Windows: pystray's win32 backend (notification area).
  Linux:   pystray's StatusNotifier/AppIndicator (falls back to XEmbed) - the
           same stack infra-monitor already ships on Quick OS Plasma.

THREADING. pystray runs its own message loop on a daemon thread and its menu
callbacks arrive ON THAT THREAD. Nothing here touches Tk: every user action is
pushed onto a Queue that the Tk side drains with root.after(). The Tk side
calls set_state() to keep the icon/tooltip current; menu item captions are
lambdas, so update_menu() re-reads them.

SECURITY. The tooltip and menu never carry a path, an entry name or any
secret - only "unlocked/locked" and a paired-browser count. Quit and "Lock
now" both route through the app's normal lock path (stop the autofill server,
clear the transport token, wipe scratch plaintext), so background mode changes
WHERE the app runs, never what locking means. The Tk side also enforces the
background auto-lock timer; the tray is display + intent only.
"""
import os, queue, sys, threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:                                    # broad guard: on a headless box the
    import pystray                      # appindicator probe raises ValueError,
    from PIL import Image, ImageDraw    # not ImportError
    HAVE_TRAY = True
except Exception:
    pystray = None
    HAVE_TRAY = False

# tray dot colours - deliberately NOT themed: the icon is painted over
# whatever the shell puts behind it (same rule as infra-monitor's tray)
DOT_UNLOCKED = "#31b558"
DOT_LOCKED   = "#9aa0a6"


def _asset(name):
    here = os.path.dirname(os.path.abspath(__file__))
    roots = [here, os.path.dirname(here)]
    if getattr(sys, "_MEIPASS", None):
        roots.insert(0, sys._MEIPASS)
    if getattr(sys, "frozen", False):
        roots.append(os.path.dirname(sys.executable))
    for r in roots:
        p = os.path.join(r, name)
        if os.path.exists(p):
            return p
    return None


def _icon_image(unlocked):
    """The app mark with a state dot. Falls back to a drawn padlock disc if
    the png is missing (never let the tray fail over a cosmetic asset)."""
    size = 64
    img = None
    png = _asset("securevault.png")
    if png:
        try:
            img = Image.open(png).convert("RGBA").resize((size, size))
        except Exception:
            img = None
    if img is None:
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.ellipse((6, 6, 58, 58), outline="#6a7cff", width=6)
        d.rectangle((24, 30, 40, 46), fill="#6a7cff")
    d = ImageDraw.Draw(img)
    colour = DOT_UNLOCKED if unlocked else DOT_LOCKED
    d.ellipse((size - 26, size - 26, size - 4, size - 4), fill=colour,
              outline="#ffffff", width=2)
    return img


class Tray:
    """One tray icon for the process lifetime. Events land in .events as
    strings: 'show' | 'lock' | 'quit'."""

    def __init__(self):
        self.events = queue.Queue()
        self.icon = None
        self._unlocked = False
        self._status = "locked"
        self._started = False

    # ---- called from the Tk side
    def available(self):
        return HAVE_TRAY

    def start(self):
        """Create + run the icon (idempotent). Returns True when the icon is
        (probably) up - some Linux backends only fail once run() executes, so
        callers should treat False/exceptions as 'close normally instead'."""
        if not HAVE_TRAY:
            return False
        if self._started:
            return True
        try:
            self.icon = pystray.Icon(
                "SecureVault", _icon_image(self._unlocked), self._tooltip(),
                menu=pystray.Menu(
                    pystray.MenuItem("Open SecureVault",
                                     lambda *_: self.events.put("show"),
                                     default=True),
                    pystray.MenuItem(lambda _i: self._status, None, enabled=False),
                    pystray.MenuItem("Lock now",
                                     lambda *_: self.events.put("lock"),
                                     enabled=lambda _i: self._unlocked),
                    pystray.Menu.SEPARATOR,
                    pystray.MenuItem("Quit (lock and exit)",
                                     lambda *_: self.events.put("quit"))))
            threading.Thread(target=self.icon.run, daemon=True,
                             name="SecureVault-Tray").start()
            self._started = True
            return True
        except Exception:
            self.icon = None
            return False

    def _tooltip(self):
        return ("SecureVault - unlocked (autofill available)" if self._unlocked
                else "SecureVault - locked")

    def set_state(self, unlocked, paired=None):
        """Update icon, tooltip and the status caption. No secrets: state word
        and a count only."""
        self._unlocked = bool(unlocked)
        if unlocked:
            n = f"{paired} paired browser(s)" if paired is not None else "autofill on"
            self._status = f"Unlocked - autofill available ({n})"
        else:
            self._status = "Locked - autofill stopped"
        if self.icon is not None:
            try:
                self.icon.icon = _icon_image(self._unlocked)
                self.icon.title = self._tooltip()
                self.icon.update_menu()
            except Exception:
                pass

    def stop(self):
        if self.icon is not None:
            try:
                self.icon.stop()
            except Exception:
                pass
            self.icon = None
        self._started = False
