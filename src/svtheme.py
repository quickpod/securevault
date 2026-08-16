#!/usr/bin/env python3
r"""
svtheme - Aura theming for SecureVault.

SecureVault's windows are ttk (Treeviews, PanedWindow, Entries, Buttons) with a
handful of raw tk widgets for the things ttk has no equivalent of - the shuffled
PIN pad, the preview panes, the notes box. That is exactly the case the Aura kit
documents as ``aura.apply(root, accent, theme)``: it restyles every ttk class
and the tk option database in one call, and this module hands the same resolved
palette to the raw widgets so nothing is left painting itself in Windows grey.

Theme preference lives in svconfig (paths-and-preferences only, still nothing
secret):

    "system"  follow the desktop's light/dark, live - the default, and what the
              QuickOpen OS shell expects of every Aura app
    "dark" / "light"    an explicit user override

A flip REBUILDS the affected windows rather than repainting them: tk fixes a
widget's colours when the widget is created, so repainting in place always
misses something. Every SecureVault window renders itself from the vault index,
so a rebuild costs nothing but the scroll position.
"""

import os
import sys
import threading
import tkinter as tk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aura

# SecureVault's per-app Aura accent - the same blue as its icon.
ACCENT = "#6c8cd5"

CYCLE = ("system", "dark", "light")
PREF_LABEL = {"system": "Theme: System", "dark": "Theme: Dark",
              "light": "Theme: Light"}

_pref = "system"


class _Theme:
    """Attribute view over the resolved palette (``TH.surface``, ``TH.text``).

    A live object, not module constants: constants bind at import time, and
    every widget would then keep whichever theme the process started in.
    """

    _d = {}

    def __getattr__(self, key):
        try:
            return _Theme._d[key]
        except KeyError:
            raise AttributeError(key)

    def get(self, key, default=None):
        return _Theme._d.get(key, default)


TH = _Theme()


def family():
    """The Aura UI family for this platform (mirrors the kit's own choice)."""
    if os.name == "nt":
        return "Segoe UI"
    if sys.platform == "darwin":
        return "Helvetica Neue"
    return "DejaVu Sans"


def mono_family():
    if os.name == "nt":
        return "Consolas"
    if sys.platform == "darwin":
        return "Menlo"
    return "DejaVu Sans Mono"


UI = family()
MONO = mono_family()


def _derive(p, mode):
    t = dict(p)
    t["mode"] = mode
    # Named roles the app talks in, mapped onto the Aura tokens so the status
    # colours move with the design system instead of being a second palette.
    t["good"] = p["ok"]
    t["warn"] = p["warn"]
    t["bad"] = p["danger"]
    return t


def apply(root=None, pref=None):
    """Resolve + activate the theme. Returns ``TH``.

    Call before building the widgets that read ``TH``. With *root* it also
    restyles ttk and, on Windows, the title bar / corners.
    """
    global _pref
    if pref:
        _pref = pref
    p = aura.apply(root, accent=ACCENT, theme=_pref)
    mode = "dark" if p["bg"] == aura.TOKENS["dark"]["bg"] else "light"
    _Theme._d = _derive(p, mode)
    return TH


def ensure(root=None):
    """Apply the SAVED preference if nothing has been applied yet.

    The password manager, the wizard and the credential prompts can each be the
    first window in a process (the CLI paths open them directly), so each one
    calls this rather than assuming svgui already ran.
    """
    if not _Theme._d:
        apply(root, load_pref())
    elif root is not None:
        aura.style_ttk(root)
        aura.windows_polish(root)
    return TH


def pref():
    return _pref


def next_pref():
    return CYCLE[(CYCLE.index(_pref) + 1) % len(CYCLE)]


def label():
    return PREF_LABEL.get(_pref, "Theme")


def load_pref():
    try:
        import svconfig
        v = svconfig.theme()
    except Exception:
        v = None
    return v if v in CYCLE else "system"


def save_pref(value):
    try:
        import svconfig
        svconfig.set_theme(value)
    except Exception:
        pass


def watch_system(callback):
    """Call ``callback('dark'|'light')`` when the OS appearance flips.

    Best-effort; the callback arrives on darkdetect's thread, so marshal onto
    the Tk thread before touching a widget.
    """
    try:
        import darkdetect
    except Exception:
        return None
    if not hasattr(darkdetect, "listener"):
        return None

    def _cb(value):
        try:
            callback("dark" if str(value).lower().startswith("d") else "light")
        except Exception:
            pass

    try:
        th = threading.Thread(target=darkdetect.listener, args=(_cb,),
                              daemon=True, name="theme")
        th.start()
        return th
    except Exception:
        return None


# ---------------------------------------------------------------- components

def beam(parent, height=2):
    """The Aura signature: a 2px accent beam fading out to the right."""
    cv = tk.Canvas(parent, height=height, highlightthickness=0, bd=0, bg=TH.bg)
    state = {"w": 0}

    def draw(_e=None):
        w = cv.winfo_width()
        if w <= 1 or w == state["w"]:
            return
        state["w"] = w
        cv.delete("all")
        fade = max(1, int(w * 0.85))
        for x in range(0, w, 3):
            cv.create_rectangle(
                x, 0, x + 3, height, width=0,
                fill=aura.mix(TH.accent, TH.bg, min(1.0, x / fade)))

    cv.bind("<Configure>", draw)
    return cv


def text(parent, **kw):
    """A raw ``tk.Text`` in Aura colours (ttk has no text widget).

    Flat, hairline-bordered, accent selection - the same treatment
    ``aura.apply`` gives ttk's entries, so a notes box or a preview pane does
    not read as a hole cut in the window.
    """
    kw.setdefault("bg", TH.field)
    kw.setdefault("fg", TH.text)
    kw.setdefault("insertbackground", TH.text)
    kw.setdefault("selectbackground", TH.accent_soft)
    kw.setdefault("selectforeground", TH.text)
    kw.setdefault("relief", "flat")
    kw.setdefault("bd", 0)
    kw.setdefault("highlightthickness", 1)
    kw.setdefault("highlightbackground", TH.border)
    kw.setdefault("highlightcolor", TH.border)
    kw.setdefault("font", (MONO, 10))
    kw.setdefault("padx", 8)
    kw.setdefault("pady", 6)
    return tk.Text(parent, **kw)


def keypad_button(parent, digit, command):
    """One key of the shuffled PIN pad.

    Raw tk rather than ttk: the pad wants a big square target with a colour
    that reacts on hover, and ttk's Button geometry is text-metric based. It is
    hand-painted in Aura tokens, and re-created on every keypress anyway (the
    shuffle), so it always matches the current theme.
    """
    b = tk.Button(parent, text=digit, width=3, command=command,
                  font=(UI, 15, "bold"),
                  bg=TH.surface2, fg=TH.text,
                  activebackground=TH.accent_soft, activeforeground=TH.text,
                  relief="flat", bd=0, highlightthickness=1,
                  highlightbackground=TH.border, highlightcolor=TH.border,
                  cursor="hand2", padx=8, pady=10)
    b.bind("<Enter>", lambda _e: b.configure(bg=TH.accent_soft))
    b.bind("<Leave>", lambda _e: b.configure(bg=TH.surface2))
    return b


class FlowBar(tk.Frame):
    """A toolbar that WRAPS instead of clipping.

    Field defect (owner's laptop, 1366x768): action rows built with
    pack(side="left") silently clip their tail when the window is narrower
    than the row - "Passwords"/"Browsers..." simply vanished at the restored
    window size. A FlowBar lays its children out grid-wise and re-flows them
    into as many rows as the current width needs, so every action stays
    reachable at ANY sane window size. Add children with .add(widget) instead
    of packing them.
    """

    def __init__(self, master, hpad=2, vpad=2, **kw):
        kw.setdefault("bg", TH.bg)
        super().__init__(master, **kw)
        self._items = []
        self._hpad, self._vpad = hpad, vpad
        self._layout = None
        self.bind("<Configure>", lambda _e: self._place())

    def add(self, widget):
        self._items.append(widget)
        self._place(force=True)
        return widget

    def _place(self, force=False):
        width = self.winfo_width()
        if width <= 1:                      # not mapped yet - try again shortly
            self.after(60, lambda: self._place(True))
            return
        x = row = col = 0
        layout = []
        for c in self._items:
            cw = c.winfo_reqwidth() + 2 * self._hpad
            if col > 0 and x + cw > width:
                row += 1
                col = 0
                x = 0
            layout.append((c, row, col))
            x += cw
            col += 1
        key = [(id(c), r, cl) for c, r, cl in layout]
        if not force and key == self._layout:
            return                          # stable: no re-grid, no loops
        self._layout = key
        for c, r, cl in layout:
            c.grid(row=r, column=cl, padx=self._hpad, pady=self._vpad,
                   sticky="w")
