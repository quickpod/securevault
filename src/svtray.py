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


def _icon_image(unlocked):
    """The state icon: an OPEN padlock in the Aura accent while unlocked, a
    CLOSED grey padlock while locked. Shape is the primary channel (open vs
    closed shackle), colour the secondary - both survive 16-22px on the light
    and the dark Plasma panel (owner requirement: the two states must be
    unmistakable at tray size). Drawn here rather than shipped as files so a
    missing asset can never blank the tray."""
    S = 64
    ACCENT = (79, 107, 255, 255)      # unlocked body - Aura accent
    GREY = (138, 144, 160, 255)      # locked body - neutral
    WHITE = (255, 255, 255, 255)
    W = 7                             # shackle stroke
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    col = ACCENT if unlocked else GREY
    if unlocked:
        # open: shackle swung up-right, left leg free of the body
        d.arc((26, 0, 58, 32), start=180, end=340, fill=col, width=W)
        d.line((58 - W // 2 + 1, 14, 58 - W // 2 + 1, 24), fill=col, width=W)
        d.rounded_rectangle((6, 28, 46, 58), radius=8, fill=col)
        d.ellipse((22, 36, 30, 44), fill=WHITE)
        d.rectangle((24, 41, 28, 51), fill=WHITE)
    else:
        # closed: shackle centred, both legs into the body
        d.arc((16, 4, 48, 36), start=180, end=360, fill=col, width=W)
        d.line((16 + W // 2 - 3, 20, 16 + W // 2 - 3, 30), fill=col, width=W)
        d.line((48 - W // 2 + 2, 20, 48 - W // 2 + 2, 30), fill=col, width=W)
        d.rounded_rectangle((12, 28, 52, 58), radius=8, fill=col)
        d.ellipse((28, 36, 36, 44), fill=WHITE)
        d.rectangle((30, 41, 34, 51), fill=WHITE)
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
