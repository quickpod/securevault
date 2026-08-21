#!/usr/bin/env python3
r"""
SecureVault GUI - an Explorer-style browser for the encrypted vault.

  - unlock with the master password (created on first run)
  - a folder TREE on the left mirrors the paths of the files you stored, with
    the file list for the selected folder on the right (double-click a folder
    row to descend, "Up" to go back)
  - live search box filters the current folder AND everything beneath it
  - Double-click a file to OPEN it in its normal Windows application. It is
    decrypted to a private scratch directory, and when the application closes
    SecureVault offers to save your edits back and then wipes the plaintext.
  - Add files / Add folder  (encrypts in, optionally deletes originals)
  - Extract selected / Extract all  (decrypts out to a folder you choose)
  - Delete selected  (removes from the vault and compacts)
  - Preview  (small text/image files decrypted in memory only - nothing hits disk)
  - Change password, Verify integrity, install the Explorer right-click menu

Runs as a standalone window. No OS keychain / registry / DPAPI is used for
secrets; the only secret is the password you type, held in memory for this
session and never stored.
"""
import os, queue, sys, threading, time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import securevault as sv
import svlock
import svsec
import svopen
import svshell
import svtheme
from svtheme import TH, UI, MONO


PIN_LEN = 6

# Treeview iid prefixes. A row is either a folder or a file and the id says
# which, so a click never has to guess from the text. Only the FIRST character
# carries the meaning; the rest of the iid is the vault path verbatim, so a
# path containing the separator is still unambiguous.
#
# These used to be "D\x00"/"F\x00". A NUL cannot survive the trip through Tcl
# on Linux - every iid was truncated at the NUL, so the second folder collided
# with the first and the window died with "Item D already exists" before it
# ever appeared. Windows/Tk tolerated it; the Linux build did not, and this app
# ships for both.
DIR_TAG  = "D:"
FILE_TAG = "F:"


class NumericPinPad(tk.Toplevel):
    r"""Randomized on-screen numeric keypad for the 6-digit PIN. Digits are
    entered with MOUSE CLICKS on a shuffled 0-9 pad, and the pad reshuffles after
    every click - so a keylogger sees no keystrokes and a mouse-position logger
    sees positions that map to different digits each time. Returns .result (str)
    or None if cancelled."""
    def __init__(self, master, prompt="Enter 6-digit PIN"):
        super().__init__(master)
        svtheme.ensure(self)
        self.title("SecureVault - PIN")
        self.configure(bg=TH.bg)
        self.result = None
        self._buf = []
        self.resizable(False, False)
        self.grab_set()

        ttk.Label(self, text=prompt + "  (click the digits)", padding=6)\
            .grid(row=0, column=0, columnspan=3, sticky="w")
        self.disp = tk.StringVar(value="")
        ttk.Entry(self, textvariable=self.disp, show="*", width=20, justify="center",
                  state="readonly").grid(row=1, column=0, columnspan=3, padx=8, pady=4)
        self.pad = ttk.Frame(self, padding=6); self.pad.grid(row=2, column=0, columnspan=3)
        self._render()

        ctrl = ttk.Frame(self, padding=6); ctrl.grid(row=3, column=0, columnspan=3)
        ttk.Button(ctrl, text="Back", command=self._back).pack(side="left", padx=3)
        ttk.Button(ctrl, text="Clear", command=self._clear).pack(side="left", padx=3)
        ttk.Button(ctrl, text="OK", command=self._ok).pack(side="left", padx=3)
        ttk.Button(ctrl, text="Cancel", command=self._cancel).pack(side="left", padx=3)
        self.protocol("WM_DELETE_WINDOW", self._cancel)   # clicks only, no key bindings

    def _render(self):
        for w in self.pad.winfo_children():
            w.destroy()
        import secrets
        digits = list("0123456789")
        for i in range(len(digits) - 1, 0, -1):           # CSPRNG shuffle
            j = secrets.randbelow(i + 1)
            digits[i], digits[j] = digits[j], digits[i]
        for idx, d in enumerate(digits):
            svtheme.keypad_button(self.pad, d,
                                  lambda c=d: self._press(c)).grid(
                                  row=idx // 5, column=idx % 5, padx=3, pady=3)

    def _press(self, d):
        if len(self._buf) < PIN_LEN:
            self._buf.append(d); self.disp.set("*" * len(self._buf))
        self._render()

    def _back(self):
        if self._buf: self._buf.pop()
        self.disp.set("*" * len(self._buf))

    def _clear(self):
        self._buf = []; self.disp.set("")

    def _ok(self):
        if len(self._buf) != PIN_LEN:
            messagebox.showerror("SecureVault", f"PIN must be {PIN_LEN} digits."); return
        self.result = "".join(self._buf); self.destroy()

    def _cancel(self):
        self.result = None; self.destroy()


def ask_pin(master, prompt="Enter 6-digit PIN"):
    pad = NumericPinPad(master, prompt=prompt)
    master.wait_window(pad)
    return pad.result


def gui_prompt_credentials(confirm=False, need_totp=True, title="SecureVault"):
    r"""Typed password + click-entered 6-digit PIN + (optional) typed authenticator
    code. Returns (password, pin, totp_code) or None. The TOTP code is a rotating
    public value, so typing it is fine; the PIN stays click-only. Creates its own
    hidden root when called from the no-console CLI path."""
    owns_root = not tk._default_root
    root = tk.Tk() if owns_root else tk._default_root
    svtheme.ensure(root)
    if owns_root:
        root.withdraw()
    try:
        pw = simpledialog.askstring(title, "Master password (typed):", show="*", parent=root)
        if not pw:
            return None
        pin = ask_pin(root, "Enter 6-digit PIN")
        if pin is None:
            return None
        if confirm:
            pw2 = simpledialog.askstring(title, "Confirm password:", show="*", parent=root)
            pin2 = ask_pin(root, "Confirm 6-digit PIN")
            if pw != pw2 or pin != pin2:
                messagebox.showerror("SecureVault", "Password or PIN did not match.")
                return None
        code = None
        if need_totp:
            code = simpledialog.askstring(title, "Authenticator (TOTP) code:", parent=root)
            if code is None:
                return None
        return (pw, pin, code)
    finally:
        if owns_root:
            root.destroy()


def human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n/1:.0f} {u}" if n < 1024 else f"{n:.1f} {u}"
        n /= 1024


def build_folder_map(index):
    r"""Group vault entry names ("docs/2026/tax.pdf") into an Explorer-style
    folder map: {folder: {"dirs": set-of-child-folders, "files": [entry names]}}.
    The vault root is the empty string. Folders are implied by the "/" in the
    stored names - the container has no separate directory records - so every
    intermediate level is created here on the way down."""
    fmap = {"": {"dirs": set(), "files": []}}
    for name in index:
        parts = [p for p in name.split("/") if p]
        if not parts:
            continue
        cur = ""
        for p in parts[:-1]:
            parent, cur = cur, (cur + "/" + p if cur else p)
            fmap.setdefault(cur, {"dirs": set(), "files": []})
            fmap[parent]["dirs"].add(cur)
        fmap[cur]["files"].append(name)
    return fmap


class App(tk.Tk):
    def __init__(self, vault, tray=None):
        super().__init__()
        # Aura first: tk fixes a widget's colours when it is created, so a
        # theme applied after _build() would only reach whatever came next.
        svtheme.apply(self, svtheme.load_pref())
        self.configure(bg=TH.bg)
        self.vault = vault
        self.tray = tray                   # shared svtray.Tray (or None)
        self._trayed = False               # window withdrawn, running in tray
        self._tray_since = 0.0
        self._locked_to_tray = False       # tells main() to keep the process
        self._last_activity = time.time()
        self.ws = svopen.Workspace(vault)
        self.cwd = ""                      # folder currently shown, "" = root
        self.index = {}
        self.fmap = {"": {"dirs": set(), "files": []}}
        self._statcache = {}
        self._next_vault = None            # set by switch_vault; read by main()
        self._set_title()
        # Fit the DEFAULT geometry to the screen (owner's laptop is 1366x768;
        # HiDPI scaling shrinks the usable logical area further) and keep the
        # minimum low: with the wrapping toolbars below, every primary action
        # stays reachable even at the minimum.
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{min(1040, sw - 40)}x{min(620, sh - 100)}")
        self.minsize(560, 400)
        self._set_window_icon()
        self._build()
        self._set_title()          # again: the header label only exists now
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.reload()
        self.after(60, lambda: self._sash())
        self.after(400, self._shell_hint)
        # start serving browser autofill while unlocked (named pipe -> svhost).
        # It stops the moment this window closes: autofill only works when the
        # app is open and unlocked, by design.
        self._autofill = None
        try:
            import svpassgui
            self._autofill = svpassgui.start_autofill(self, self.vault)
        except Exception:
            self._autofill = None
        # Follow the desktop's Aura Dark/Light while the preference is
        # "system". darkdetect's listener runs on its own thread, so the change
        # is marshalled onto the Tk loop before any widget is touched.
        svtheme.watch_system(
            lambda mode: self.after(0, lambda m=mode: self._system_theme(m)))
        # freshly-created vaults may want the autofill wizard offered once
        if getattr(vault, "_sv_freshly_created", False):
            self.after(600, self._maybe_offer_wizard)
        # tray-menu intents (Open/Lock/Quit) arrive via a queue; drain on Tk
        if self.tray is not None:
            self.after(300, self._tray_events)
            # Assert the unlocked state UNCONDITIONALLY. This used to be gated
            # on tray._started, so on an ordinary launch (no --locked autostart,
            # nothing trayed yet) it never ran and the Tray object still held
            # _unlocked=False for the whole unlocked session. Consequences:
            # start() later built the CLOSED-padlock image, the tooltip read
            # "locked", and the "Lock now" menu item - enabled=lambda: _unlocked
            # - stayed greyed out on an unlocked vault. set_state() is safe
            # before the icon exists; it just records the state that a later
            # start() reads.
            self._tray_state()
        # SYSTEM auto-lock triggers (1.0.9, owner field feedback: the vault
        # must never lock mid-work). Primary: desktop lock / screensaver /
        # suspend, watched by svlock.Monitor on its own thread and marshalled
        # here via a queue. Fallback: the _autolock_tick timer below, measured
        # against SYSTEM input idle - so using other apps counts as activity.
        self._sys_events = queue.Queue()
        self._sysmon = svlock.Monitor(self._sys_events.put)
        try:
            self._sysmon.start()
        except Exception:
            pass
        self.after(500, self._sys_events_tick)
        self.after(30_000, self._autolock_tick)
        # first successful open on this machine turns login-autostart on by
        # default (explicit off in Preferences is never overridden)
        try:
            import svautostart
            svautostart.ensure_default()
        except Exception:
            pass

    def _set_title(self):
        self.title(f"SecureVault — {os.path.basename(self.vault.path)} "
                   f"({self.vault.path}) — quickopen.ai")
        # The header carries the same thing in the window itself, because a
        # title bar is the first thing a screenshot or a maximised window loses.
        lbl = getattr(self, "vault_label", None)
        if lbl is not None:
            # Home collapsed to ~: the header is for orienting yourself among
            # several vaults, and an absolute path long enough to push the
            # theme control off the edge orients nobody. The full path is a
            # hover away in the title bar.
            disp, home = self.vault.path, os.path.expanduser("~")
            if home and disp.startswith(home + os.sep):
                disp = "~" + disp[len(home):]
            try:
                lbl.configure(text=disp)
            except tk.TclError:
                pass

    # ---------- layout
    def _asset_path(self, name):
        """Locate a bundled asset from source or a PyInstaller one-file build."""
        import sys
        roots = []
        if getattr(sys, "_MEIPASS", None):
            roots.append(sys._MEIPASS)
        here = os.path.dirname(os.path.abspath(__file__))
        roots += [here, os.path.dirname(here), os.path.dirname(sys.executable)]
        for r in roots:
            p = os.path.join(r, name)
            if os.path.exists(p):
                return p
        return None

    def _set_window_icon(self):
        try:
            ico = self._asset_path("securevault.ico")
            if ico:
                self.iconbitmap(ico)
        except Exception:
            pass  # icon is cosmetic; never block launch on it

    def _build(self):
        self._menubar()

        # ---- Aura header: brand mark, vault name, theme control, then the
        # signature accent beam. The same header every QuickOpen app carries.
        head = ttk.Frame(self, padding=(12, 12, 12, 9)); head.pack(fill="x")
        self._brand_icon = None
        try:
            png = self._asset_path("securevault.png")
            if png:
                img = tk.PhotoImage(file=png, master=self)
                k = max(1, round(img.width() / 22))
                self._brand_icon = img.subsample(k, k)   # kept: tk drops unref'd
                tk.Label(head, image=self._brand_icon, bd=0, bg=TH.bg)\
                    .pack(side="left", padx=(0, 9))
        except Exception:
            self._brand_icon = None
        ttk.Label(head, text="SecureVault", font=(UI, 13, "bold"))\
            .pack(side="left")
        self.vault_label = ttk.Label(head, text="", style="Muted.TLabel")
        self.vault_label.pack(side="left", padx=(14, 0))
        self._theme_btn = ttk.Button(head, text=svtheme.label(),
                                     command=self.cycle_theme)
        self._theme_btn.pack(side="right")
        svtheme.beam(self).pack(fill="x")

        # Buttons pack FIRST (from the right), the search entry last with the
        # leftover: pack clips whatever was packed LAST when width runs out,
        # so this order means a narrow window shrinks the search box instead
        # of hiding actions (field defect: "Passwords" vanished at restored
        # size on a 1366x768 laptop).
        top = ttk.Frame(self, padding=(8, 10, 8, 4)); top.pack(fill="x")
        ttk.Label(top, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh())
        for txt, cmd, style in (("Browsers", self.open_browsers, None),
                                ("Passwords", self.open_passwords, None),
                                ("Add Folder", self.add_folder, None),
                                ("Add Files", self.add_files, "Accent.TButton")):
            kw = {"style": style} if style else {}
            ttk.Button(top, text=txt, command=cmd, **kw).pack(side="right", padx=2)
        e = ttk.Entry(top, textvariable=self.search_var, width=12)
        e.pack(side="left", fill="x", expand=True, padx=6)
        e.focus_set()

        self.pan = ttk.PanedWindow(self, orient="horizontal")
        self.pan.pack(fill="both", expand=True, padx=8)

        # --- left: folder tree
        left = ttk.Frame(self.pan)
        ttk.Label(left, text="Folders", anchor="w", padding=(2, 0, 0, 3)).pack(fill="x")
        # height=5: a Treeview's DEFAULT minimum is 10 rows, and pack clips
        # the LAST-packed widgets when height runs out - which was the bottom
        # action bar at small window heights (same clipping class as the
        # horizontal field defect, vertically). 5 rows keeps every bar visible
        # at the 400px minimum; the tree still expands to fill real estate.
        self.folders = ttk.Treeview(left, show="tree", selectmode="browse",
                                    height=5)
        lvs = ttk.Scrollbar(left, orient="vertical", command=self.folders.yview)
        self.folders.configure(yscrollcommand=lvs.set)
        lvs.pack(side="right", fill="y")
        self.folders.pack(side="left", fill="both", expand=True)
        self.folders.bind("<<TreeviewSelect>>", self._on_folder_select)
        self.pan.add(left, weight=1)

        # --- right: path bar + file list
        right = ttk.Frame(self.pan)
        nav = ttk.Frame(right); nav.pack(fill="x", pady=(0, 4))
        ttk.Button(nav, text="Up", width=5, command=self.go_up).pack(side="left")
        self.path_var = tk.StringVar(value="/")
        ttk.Label(nav, textvariable=self.path_var, anchor="w", padding=(8, 4),
                  background=TH.field, foreground=TH.muted)\
            .pack(side="left", fill="x", expand=True, padx=6)

        cols = ("name", "size", "type", "modified", "source")
        self.tree = ttk.Treeview(right, columns=cols, show="headings",
                                 selectmode="extended", height=5)
        for c, w in (("name", 300), ("size", 95), ("type", 115), ("modified", 165), ("source", 170)):
            self.tree.heading(c, text=c.title(), command=lambda cc=c: self.sort_by(cc))
            self.tree.column(c, width=w, anchor="w", stretch=(c == "name"))
        rvs = ttk.Scrollbar(right, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=rvs.set)
        rvs.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-1>", self._on_row_activate)
        self.tree.bind("<Return>", self._on_row_activate)
        self.tree.bind("<BackSpace>", lambda e: self.go_up())
        self.tree.tag_configure("dir", font=(UI, 10, "bold"))
        self.pan.add(right, weight=4)

        # --- checked-out files (packed only while something is open)
        self.openbar = ttk.Frame(self, padding=(8, 4))
        self.open_var = tk.StringVar(value="")
        ttk.Label(self.openbar, textvariable=self.open_var, anchor="w",
                  foreground=TH.warn).pack(side="left", fill="x", expand=True)
        ttk.Button(self.openbar, text="I'm done - close & wipe",
                   command=self.finish_open).pack(side="right", padx=3)

        # A wrapping bar: seven buttons never fit one row on a small screen,
        # and clipped buttons are buttons that do not exist (field defect).
        self.bottombar = svtheme.FlowBar(self, hpad=3, vpad=3)
        self.bottombar.pack(fill="x", padx=8, pady=(4, 4))
        for txt, cmd in (("Open", self.open_external), ("Preview", self.preview),
                         ("Extract Selected", self.extract_sel), ("Extract All", self.extract_all),
                         ("Delete", self.delete_sel), ("Verify", self.verify),
                         ("Change Password", self.change_pw)):
            self.bottombar.add(ttk.Button(self.bottombar, text=txt, command=cmd))

        self.status = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.status, anchor="w",
                  padding=(12, 6), background=TH.bg2, foreground=TH.muted)\
            .pack(fill="x", side="bottom")
        self._sort = ("name", False)

    def _menubar(self):
        bar = tk.Menu(self)

        filem = tk.Menu(bar, tearoff=0)
        filem.add_command(label="New Vault...", command=lambda: self.switch_vault("new"))
        filem.add_command(label="Open Vault...", command=lambda: self.switch_vault("open"))
        self._recent_menu = tk.Menu(filem, tearoff=0)
        filem.add_cascade(label="Open Recent", menu=self._recent_menu)
        self._fill_recent_menu()
        filem.add_separator()
        filem.add_command(label="Exit", command=self._on_close)
        bar.add_cascade(label="File", menu=filem)

        tools = tk.Menu(bar, tearoff=0)
        tools.add_command(label=f"Install / repoint {svshell.MENU_NAME}",
                          command=self.shell_register)
        tools.add_command(label=f"Remove {svshell.MENU_NAME}", command=self.shell_unregister)
        tools.add_command(label=f"{svshell.MENU_NAME.capitalize()} status...",
                          command=self.shell_status)
        tools.add_separator()
        tools.add_command(label="Verify integrity", command=self.verify)
        tools.add_command(label="Vault info...", command=self.vault_info)
        tools.add_command(label="Change password / PIN", command=self.change_pw)
        tools.add_separator()
        tools.add_command(label="Passwords (manager)...", command=self.open_passwords)
        tools.add_command(label="Set up browser autofill...", command=self.setup_autofill)
        tools.add_command(label="Import passwords from browser...", command=self.import_passwords)
        tools.add_separator()
        tools.add_command(label="Preferences (background && auto-lock)...",
                          command=lambda: PreferencesDialog(self))
        bar.add_cascade(label="Tools", menu=tools)

        view = tk.Menu(bar, tearoff=0)
        view.add_command(label="Switch theme (System / Dark / Light)",
                         command=self.cycle_theme)
        bar.add_cascade(label="View", menu=view)

        helpm = tk.Menu(bar, tearoff=0)
        helpm.add_command(label="SecureVault Help", accelerator="F1",
                          command=self.show_help)
        helpm.add_command(label="Browser pairing & extension setup...",
                          command=lambda: self.show_help("pairing"))
        helpm.add_command(label="Install the extension (Chrome/Edge)...",
                          command=lambda: self.show_help("install the extension"))
        bar.add_cascade(label="Help", menu=helpm)
        self.bind("<F1>", lambda _e: self.show_help())

        # The menuBAR strip is drawn by the window manager and ignores colours;
        # the drop-downs do not, and aura.track keeps them on the palette
        # through a theme flip. (This is why the Aura scaffold hides the native
        # bar entirely - here the menus predate the retrofit and stay.)
        for m in (bar, filem, tools, view, helpm, self._recent_menu):
            try:
                svtheme.aura.track(m, "menu")
            except Exception:
                pass
        self.configure(menu=bar)

    def _fill_recent_menu(self):
        """Populate File > Open Recent from the (paths-only) config."""
        try:
            import svconfig
            recent = svconfig.recent_vaults()
        except Exception:
            recent = []
        self._recent_menu.delete(0, "end")
        cur = os.path.abspath(self.vault.path)
        shown = [p for p in recent if os.path.abspath(p) != cur]
        if not shown:
            self._recent_menu.add_command(label="(none)", state="disabled")
            return
        for p in shown:
            exists = os.path.isfile(p)
            label = p if exists else p + "   (missing)"
            self._recent_menu.add_command(
                label=label,
                command=(lambda pp=p: self._open_recent(pp)) if exists else (lambda: None),
                state=("normal" if exists else "disabled"))

    def _sash(self):
        try:
            self.pan.sashpos(0, 250)
        except Exception:
            pass

    # ---------- appearance
    def cycle_theme(self):
        """System -> Dark -> Light, saved so the choice survives a restart."""
        pref = svtheme.next_pref()
        svtheme.save_pref(pref)
        self._retheme(pref)

    def _system_theme(self, mode):
        """The desktop flipped Aura Dark/Light - follow it, unless overridden."""
        if svtheme.pref() != "system" or mode == TH.mode:
            return
        self._retheme()

    def _retheme(self, pref=None):
        """Rebuild the window in the resolved theme.

        tk binds a colour when a widget is created, so a flip means building the
        window again rather than repainting every widget in place and missing
        some. Everything on screen is derived from the vault index, so the
        rebuild costs a redraw - and never a re-unlock: the vault handle, the
        open-file workspace and the autofill server all outlive the widgets."""
        svtheme.apply(self, pref)
        self.configure(bg=TH.bg)
        for w in list(self.winfo_children()):
            try:
                w.destroy()
            except Exception:
                pass
        self._build()
        self._set_title()
        self.reload()
        self._refresh_open()
        self.after(60, self._sash)

    # ---------- data
    def reload(self):
        try:
            self.index = self.vault.list()
        except sv.VaultError as ex:
            messagebox.showerror("SecureVault", str(ex)); self.index = {}
        self.fmap = build_folder_map(self.index)
        self._statcache = {}
        if self.cwd not in self.fmap:
            self.cwd = ""
        self._fill_folders()
        self.refresh()

    def _fill_folders(self):
        """Rebuild the left tree, keeping whatever the user had expanded."""
        opened = set()
        def collect(iid):
            for c in self.folders.get_children(iid):
                if self.folders.item(c, "open"):
                    opened.add(c)
                collect(c)
        collect("")
        self.folders.delete(*self.folders.get_children())
        root = DIR_TAG
        self.folders.insert("", "end", iid=root, text="SecureVault", open=True)
        def add(parent_iid, path):
            for d in sorted(self.fmap[path]["dirs"], key=str.lower):
                iid = DIR_TAG + d
                self.folders.insert(parent_iid, "end", iid=iid, text=d.split("/")[-1],
                                    open=(iid in opened))
                add(iid, d)
        add(root, "")
        want = DIR_TAG + self.cwd
        self._select_folder(want if self.folders.exists(want) else root)

    def _select_folder(self, iid):
        """Select without letting the resulting event re-enter refresh twice."""
        self._muted = True
        try:
            self.folders.selection_set(iid)
            self.folders.see(iid)
        finally:
            self._muted = False

    def _stats(self, folder):
        """(files, bytes, newest mtime) for a folder and everything under it."""
        if folder in self._statcache:
            return self._statcache[folder]
        node = self.fmap.get(folder)
        if node is None:
            return (0, 0, 0)
        n = len(node["files"])
        size = sum(self.index[f]["size"] for f in node["files"])
        mt = max((self.index[f].get("mtime", 0) for f in node["files"]), default=0)
        for d in node["dirs"]:
            dn, ds, dm = self._stats(d)
            n += dn; size += ds; mt = max(mt, dm)
        self._statcache[folder] = (n, size, mt)
        return self._statcache[folder]

    def refresh(self):
        import datetime
        q = self.search_var.get().lower().strip()
        self.tree.delete(*self.tree.get_children())
        if self.cwd not in self.fmap:
            self.cwd = ""
        self.path_var.set("/" + self.cwd)

        rows = []                            # (is_dir, display, key, size, mtime, src)
        if q:
            # Explorer-style search: this folder and everything beneath it.
            prefix = self.cwd + "/" if self.cwd else ""
            for name, ent in self.index.items():
                if not name.startswith(prefix):
                    continue
                rel = name[len(prefix):]
                if q in rel.lower():
                    rows.append((False, rel, name, ent["size"],
                                 ent.get("mtime", 0), ent.get("src", "")))
        else:
            for d in self.fmap[self.cwd]["dirs"]:
                n, size, mt = self._stats(d)
                rows.append((True, d.split("/")[-1], d, size, mt, f"{n} file(s)"))
            for name in self.fmap[self.cwd]["files"]:
                ent = self.index[name]
                rows.append((False, name.split("/")[-1], name, ent["size"],
                             ent.get("mtime", 0), ent.get("src", "")))

        key, rev = self._sort
        def sk(r):
            is_dir, disp, k, size, mt, src = r
            return {"name": disp.lower(), "size": size, "type": "" if is_dir
                    else os.path.splitext(disp)[1].lower(),
                    "modified": mt, "source": (src or "").lower()}[key]
        rows.sort(key=sk, reverse=rev)
        rows.sort(key=lambda r: not r[0])    # folders first, like Explorer

        nd = nf = 0
        for is_dir, disp, k, size, mt, src in rows:
            mts = datetime.datetime.fromtimestamp(mt).strftime("%Y-%m-%d %H:%M") if mt else ""
            if is_dir:
                nd += 1
                self.tree.insert("", "end", iid=DIR_TAG + k, tags=("dir",),
                                 values=(disp, human(size), "File folder", mts, src))
            else:
                nf += 1
                ext = os.path.splitext(disp)[1].lower()
                open_mark = "  [open]" if self.ws.is_open(k) else ""
                self.tree.insert("", "end", iid=FILE_TAG + k,
                                 values=(disp + open_mark, human(size),
                                         (ext[1:].upper() + " file") if ext else "File", mts, src))
        total = sum(e["size"] for e in self.index.values())
        where = "search results" if q else ("/" + self.cwd)
        self.status.set(f"{where}:  {nd} folder(s), {nf} file(s)   |   "
                        f"vault total {len(self.index)} file(s), {human(total)}")

    def sort_by(self, col):
        key, rev = self._sort
        self._sort = (col, not rev if key == col else False)
        self.refresh()

    # ---------- navigation
    def _on_folder_select(self, _e=None):
        if getattr(self, "_muted", False):
            return
        sel = self.folders.selection()
        if not sel:
            return
        self.cwd = sel[0][len(DIR_TAG):]
        self.refresh()

    def navigate(self, path):
        iid = DIR_TAG + path
        if self.folders.exists(iid):
            p = self.folders.parent(iid)
            while p:
                self.folders.item(p, open=True)
                p = self.folders.parent(p)
            self.folders.selection_set(iid)      # fires _on_folder_select -> refresh
            self.folders.see(iid)
        else:
            self.cwd = path
            self.refresh()

    def go_up(self):
        if not self.cwd:
            return
        self.navigate(self.cwd.rsplit("/", 1)[0] if "/" in self.cwd else "")

    def _on_row_activate(self, _e=None):
        sel = self.tree.selection()
        if not sel:
            return
        if sel[0].startswith(DIR_TAG):
            self.navigate(sel[0][len(DIR_TAG):])
        else:
            self.open_external()

    # ---------- selection
    def _selected(self):
        """Selected entry names. A folder row expands to everything under it."""
        names, seen = [], set()
        for iid in self.tree.selection():
            if iid.startswith(DIR_TAG):
                p = iid[len(DIR_TAG):]
                hits = [n for n in self.index if n == p or n.startswith(p + "/")]
            else:
                hits = [iid[len(FILE_TAG):]]
            for n in hits:
                if n not in seen:
                    seen.add(n); names.append(n)
        return names

    def _selected_files(self):
        """Only file rows - actions like Open/Preview must not expand a folder."""
        return [iid[len(FILE_TAG):] for iid in self.tree.selection()
                if iid.startswith(FILE_TAG)]

    def _rel(self, name):
        """Path to use when extracting, relative to the folder being viewed."""
        prefix = self.cwd + "/" if self.cwd else ""
        return name[len(prefix):] if name.startswith(prefix) else os.path.basename(name)

    # ---------- background helper
    def _bg(self, fn, done=None):
        """Run a slow op off the UI thread, then refresh."""
        def run():
            try:
                fn()
                err = None
            except Exception as ex:
                err = str(ex)
            self.after(0, lambda: self._after_bg(err, done))
        self.status.set("working...")
        threading.Thread(target=run, daemon=True).start()

    def _after_bg(self, err, done):
        if err:
            messagebox.showerror("SecureVault", err)
        self.reload()
        if done:
            done()

    def _run(self, fn, done):
        """Like _bg but hands the result to done(result, error) and does NOT
        reload - for work that does not change the vault."""
        def work():
            try:
                r, err = fn(), None
            except Exception as ex:
                r, err = None, str(ex)
            self.after(0, lambda: done(r, err))
        threading.Thread(target=work, daemon=True).start()

    # ---------- open outside the vault
    def open_external(self):
        names = self._selected_files()
        if not names:
            self.status.set("select a file to open"); return
        if len(names) > 5 and not messagebox.askyesno(
                "SecureVault", f"Open {len(names)} files in their applications?"):
            return
        for n in names:
            self._open_one(n)

    def _open_one(self, name):
        if self.ws.is_open(name):
            self.status.set(f"{name} is already open"); return
        self.status.set(f"decrypting {name}...")
        def done(entry, err):
            if err:
                messagebox.showerror("SecureVault", f"Could not open {name}:\n{err}"); return
            try:
                self.ws.launch(entry, self._on_ext_closed)
            except svopen.OpenError as ex:
                # No handler for this extension. Offer Windows' own picker
                # rather than letting the shell pop it modally on top of us.
                if "associated" in str(ex) and messagebox.askyesno("SecureVault",
                        f"Windows has no application registered for:\n\n  {name}\n\n"
                        "Choose one now?"):
                    try:
                        self.ws.launch(entry, self._on_ext_closed, picker=True)
                    except Exception as ex2:
                        self.ws.discard(name)
                        messagebox.showerror("SecureVault", f"Could not open {name}:\n{ex2}")
                        self._refresh_open(); return
                else:
                    self.ws.discard(name)       # nothing launched: wipe it again
                    if "associated" not in str(ex):
                        messagebox.showerror("SecureVault", f"Could not open {name}:\n{ex}")
                    self.status.set(f"{name}: not opened, plaintext wiped")
                    self._refresh_open(); return
            except Exception as ex:
                self.ws.discard(name)
                messagebox.showerror("SecureVault", f"Could not open {name}:\n{ex}")
                self._refresh_open(); return
            if entry["detect"] == "handle":
                self.status.set(f"{name} is open - it will be wiped when the app closes")
            else:
                self.status.set(f"{name} is open - watching for the app to release it")
            self._refresh_open()
            self.refresh()
        self._run(lambda: self.ws.stage(name), done)

    def _on_ext_closed(self, name, detect):
        """Called from the watcher thread - hop back to the UI thread."""
        self.after(0, lambda: self._closed_ui(name, detect))

    def _closed_ui(self, name, detect):
        if detect == "manual":
            self.status.set(f"{name}: cannot tell when this app closes - "
                            f"use \"I'm done\" when you have finished with it")
            self._refresh_open()
            return
        save = False
        if self.ws.changed(name):
            save = messagebox.askyesno(
                "SecureVault - save changes?",
                f"{name}\n\nwas modified while it was open.\n\n"
                "Yes  - save the new version back into the vault\n"
                "No   - discard the edits\n\n"
                "Either way the decrypted copy is wiped now.")
        self._finish(name, save)

    def _finish(self, name, save):
        def work():
            self.ws.finish(name, save_back=save)
        self._bg(work, done=lambda: (
            self._refresh_open(),
            self.status.set(f"{name}: " + ("saved back to the vault, plaintext wiped"
                                           if save else "closed, plaintext wiped"))))

    def finish_open(self):
        """The 'I'm done' button: settle every checked-out file at once."""
        ents = self.ws.list_open()
        if not ents:
            return
        pending = []
        for e in ents:
            save = False
            if self.ws.changed(e["name"]):
                save = messagebox.askyesno(
                    "SecureVault - save changes?",
                    f"{e['name']}\n\nwas modified.\n\nSave the changes back into the vault?")
            pending.append((e["name"], save))
        def work():
            for n, s in pending:
                self.ws.finish(n, save_back=s)
        saved = sum(1 for _n, s in pending if s)
        self._bg(work, done=lambda: (
            self._refresh_open(),
            self.status.set(f"closed and wiped {len(pending)} file(s), "
                            f"{saved} saved back to the vault")))

    def _refresh_open(self):
        ents = self.ws.list_open()
        if not ents:
            self.openbar.pack_forget()
        else:
            names = ", ".join(e["name"] for e in ents[:4])
            more = f" (+{len(ents) - 4} more)" if len(ents) > 4 else ""
            self.open_var.set(f"Decrypted outside the vault: {names}{more}")
            self.openbar.pack(fill="x", before=self.bottombar)
        try:
            self.refresh()
        except Exception:
            pass

    # ---------- actions
    def add_files(self):
        paths = filedialog.askopenfilenames(title="Add files to the vault")
        if not paths:
            return
        delete = messagebox.askyesno("SecureVault",
                    "Delete the original file(s) after adding to the vault?")
        dest = self.cwd
        def work():
            for p in paths:
                arc = (dest + "/" + os.path.basename(p)) if dest else os.path.basename(p)
                self.vault.add(p, arcname=arc, delete_original=delete)
        self._bg(work)

    def add_folder(self):
        d = filedialog.askdirectory(title="Add a folder to the vault")
        if not d:
            return
        delete = messagebox.askyesno("SecureVault",
                    "Delete the original files after adding to the vault?")
        dest = self.cwd
        def work():
            base = os.path.dirname(d.rstrip("/\\"))
            for dp, dn, fn in os.walk(d):
                for n in fn:
                    fp = os.path.join(dp, n)
                    rel = os.path.relpath(fp, base).replace(os.sep, "/")
                    self.vault.add(fp, arcname=(dest + "/" + rel) if dest else rel,
                                   delete_original=delete)
        self._bg(work)

    def extract_sel(self):
        names = self._selected()
        if not names:
            return
        d = filedialog.askdirectory(title="Extract selected to...")
        if not d:
            return
        self._bg(lambda: [self.vault.get(n, os.path.join(d, self._rel(n))) for n in names],
                 done=lambda: self.status.set(f"extracted {len(names)} file(s)"))

    def extract_all(self):
        d = filedialog.askdirectory(title="Extract ALL to...")
        if not d:
            return
        self._bg(lambda: [self.vault.get(n, os.path.join(d, n)) for n in list(self.index)],
                 done=lambda: self.status.set("extracted all"))

    def delete_sel(self):
        names = self._selected()
        if not names:
            return
        busy = [n for n in names if self.ws.is_open(n)]
        if busy:
            messagebox.showwarning("SecureVault",
                "These are currently open outside the vault. Close them first:\n\n  "
                + "\n  ".join(busy))
            return
        if not messagebox.askyesno("SecureVault",
                f"Permanently delete {len(names)} file(s) from the vault?\nThis cannot be undone."):
            return
        def work():
            for n in names:
                self.vault.remove(n)
        self._bg(work)

    def preview(self):
        names = self._selected_files()
        if not names:
            return
        name = names[0]
        try:
            data = self.vault.read_bytes(name)      # in memory only
        except sv.VaultError as ex:
            messagebox.showerror("SecureVault", str(ex)); return
        win = tk.Toplevel(self); win.title(f"Preview - {name}"); win.geometry("640x480")
        win.configure(bg=TH.bg)
        ext = os.path.splitext(name)[1].lower()
        if ext in (".png", ".gif", ".ppm", ".pgm"):
            try:
                img = tk.PhotoImage(data=data)
                lbl = tk.Label(win, image=img, bd=0, bg=TH.bg)
                lbl.image = img; lbl.pack(expand=True)
                return
            except Exception:
                pass
        txt = svtheme.text(win, wrap="none")
        try:
            preview = data[:200_000].decode("utf-8")
        except UnicodeDecodeError:
            preview = f"[binary file, {len(data)} bytes]\n\n" + data[:2000].hex()
        txt.insert("1.0", preview); txt.configure(state="disabled"); txt.pack(fill="both", expand=True)

    def verify(self):
        def work():
            idx, bad = self.vault.verify()
            msg = f"All {len(idx)} file(s) authenticated OK." if not bad \
                  else "FAILURES:\n" + "\n".join(f"{n}: {r}" for n, r in bad)
            self.after(0, lambda: messagebox.showinfo("SecureVault - Verify", msg))
        self._bg(work)

    def vault_info(self):
        total = sum(e["size"] for e in self.index.values())
        try:
            dead = self.vault.dead_space()
        except Exception:
            dead = 0
        messagebox.showinfo("SecureVault - vault info",
            f"Container : {self.vault.path}\n"
            f"On disk   : {human(os.path.getsize(self.vault.path))}\n"
            f"Files     : {len(self.index)}  ({human(total)} decrypted)\n"
            f"Folders   : {len(self.fmap) - 1}\n"
            f"Reclaimable: {human(dead)} of superseded blobs\n"
            "  (left by saving an edited file back; a Delete compacts it away)")

    def open_passwords(self):
        # the vault is already unlocked in this session, so no second prompt
        import svpassgui
        try:
            svpassgui.open_manager(self, self.vault)
        except Exception as ex:
            messagebox.showerror("SecureVault", f"Could not open the password manager:\n{ex}")

    def open_browsers(self):
        """Browser integration, one click from the main window (field ask):
        the pairing dialog with the paired list, PIN flow and bookmarks
        backup status."""
        import svpassgui
        if not getattr(self, "_autofill", None):
            messagebox.showerror("SecureVault",
                                 "The autofill service is not running.")
            return
        try:
            svpassgui.open_pairing(self, self._autofill)
        except Exception as ex:
            messagebox.showerror("SecureVault", f"Could not open browser "
                                                f"integration:\n{ex}")

    # ---------- help
    def show_help(self, topic=None):
        try:
            import svhelp
            svhelp.show(self, topic=topic)
        except Exception as ex:
            messagebox.showerror("SecureVault", f"Could not open help:\n{ex}")

    # ---------- browser autofill wizards
    def setup_autofill(self):
        try:
            import svwizard
            svwizard.launch_autofill_setup(master=self, app=self)
        except Exception as ex:
            messagebox.showerror("SecureVault", f"Could not open the setup wizard:\n{ex}")

    def import_passwords(self):
        try:
            import svwizard
            svwizard.launch_password_import(master=self, app=self, vault=self.vault)
        except Exception as ex:
            messagebox.showerror("SecureVault", f"Could not open the import wizard:\n{ex}")

    def _maybe_offer_wizard(self):
        try:
            self.vault._sv_freshly_created = False   # offer only once
        except Exception:
            pass
        if messagebox.askyesno(
                "SecureVault",
                "Your vault is ready.\n\nSet up browser autofill now so you can "
                "fill and save logins from Chrome, Edge or Brave?\n\n"
                "(You can always do this later from Tools > Set up browser autofill.)"):
            self.setup_autofill()

    # ---------- switch / open a different vault
    def _open_recent(self, path):
        self._switch_to(path, mode="open")

    def switch_vault(self, mode):
        """File > New/Open Vault: pick a location, create/unlock it, and swap the
        whole window over to it (main() reopens the App on the new vault)."""
        if mode == "new":
            path = filedialog.asksaveasfilename(
                parent=self, title="Create new vault", defaultextension=".dat",
                initialfile="SecureVault.dat",
                filetypes=[("SecureVault container", "*.dat"), ("All files", "*.*")])
        else:
            path = filedialog.askopenfilename(
                parent=self, title="Open vault",
                filetypes=[("SecureVault container", "*.dat"), ("All files", "*.*")])
        if not path:
            return
        self._switch_to(path, mode=mode)

    def _switch_to(self, path, mode):
        if os.path.abspath(path) == os.path.abspath(self.vault.path):
            messagebox.showinfo("SecureVault", "That vault is already open."); return
        if mode == "new" and os.path.isfile(path):
            if not messagebox.askyesno(
                    "SecureVault",
                    f"A file already exists at:\n{path}\n\nOpen it as an existing "
                    "vault instead?"):
                return
            mode = "open"
        # build/unlock the target vault BEFORE tearing down the current one, so a
        # cancel or wrong password leaves the current session untouched.
        if mode == "new":
            vault = _create_vault_at(self, path)
        else:
            vault = _unlock_vault_at(self, path)
        if vault is None:
            return
        if not self._confirm_discard_open():
            return
        self._next_vault = vault           # main() picks this up after we close
        if getattr(self, "_autofill", None):
            self._autofill.stop()
        self.ws.wipe_all()
        self.destroy()

    def _confirm_discard_open(self):
        """If files are checked out, confirm before switching away (which wipes
        the decrypted copies). Returns True to proceed."""
        ents = self.ws.list_open()
        if not ents:
            return True
        changed = [e["name"] for e in ents if self.ws.changed(e["name"])]
        msg = (f"{len(ents)} file(s) are still decrypted outside the vault.\n")
        if changed:
            msg += ("\nUNSAVED EDITS in:\n  " + "\n  ".join(changed)
                    + "\n\nUse \"I'm done - close & wipe\" first to keep them.\n")
        msg += "\nSwitching vaults wipes every decrypted copy now. Continue?"
        return messagebox.askokcancel("SecureVault", msg)

    def change_pw(self):
        creds = gui_prompt_credentials(confirm=True, need_totp=False, title="New password + PIN")
        if not creds:
            return
        self.vault.change_password(sv.auth_material(creds[0].encode("utf-8"),
                                                    creds[1].encode("utf-8")))
        messagebox.showinfo("SecureVault", "Master password and PIN changed.")

    # ---------- shell integration
    def shell_register(self):
        try:
            exe = svshell.register()
        except Exception as ex:
            messagebox.showerror("SecureVault",
                f"Could not install the {svshell.MENU_NAME}:\n{ex}")
            return
        where = ("  Right-click a file    -> Send to SV (Secure Vault)\n"
                 "  Right-click a folder  -> Send folder to SV\n"
                 "  Right-click a backdrop-> Open Secure Vault\n"
                 if os.name == "nt" else
                 "  Right-click files/folders in Dolphin -> Send to SV (Secure Vault)\n"
                 "  (KDE file manager; other desktops: use Add Files in this window)\n")
        messagebox.showinfo("SecureVault",
            f"{svshell.MENU_NAME.capitalize()} installed for your user account.\n\n"
            + where + f"\nPointing at:\n{exe}")
        self.status.set(f"{svshell.MENU_NAME} installed")

    def shell_unregister(self):
        try:
            svshell.unregister()
        except Exception as ex:
            messagebox.showerror("SecureVault", str(ex)); return
        messagebox.showinfo("SecureVault", f"{svshell.MENU_NAME.capitalize()} removed.")

    def shell_status(self):
        messagebox.showinfo(f"SecureVault - {svshell.MENU_NAME}", svshell.status_text())

    def _shell_hint(self):
        """Mention a missing or stale menu once in the status bar. No dialog -
        the registry is only ever touched when you ask for it."""
        try:
            installed, _cmd = svshell.is_registered()
            current = svshell.is_current()
        except Exception:
            return
        if not installed:
            self.status.set(f"Tip: Tools > Install {svshell.MENU_NAME} "
                            "to get 'Send to SV' back.")
        elif not current:
            self.status.set(f"Tip: the {svshell.MENU_NAME} points at a different copy "
                            "of SecureVault - Tools > Install / repoint to fix it.")

    # ---------- background (tray) mode
    def note_activity(self):
        """Thread-safe: autofill worker threads call this on every authorized
        request. Since 1.0.9 this is only the LAST-RESORT idle signal, used
        when no system input-idle source exists (svlock.idle_ms() -> None) -
        autofill activity by itself no longer keeps the vault unlocked; real
        keyboard/mouse input does."""
        self._last_activity = time.time()

    def _tray_events(self):
        """Drain tray-menu intents (they arrive on pystray's thread via a
        queue) onto the Tk thread. Runs for the App's whole life."""
        try:
            while self.tray is not None:
                evt = self.tray.events.get_nowait()
                if evt == "show":
                    self._show_from_tray()
                elif evt == "lock":
                    self._lock_from_tray()
                elif evt == "quit":
                    self._quit_from_tray()
        except Exception:
            pass                            # queue.Empty and teardown races
        try:
            self.after(250, self._tray_events)
        except Exception:
            pass

    def _tray_state(self):
        if self.tray is None:
            return
        try:
            n = len(self._autofill.paired_clients()) if self._autofill else 0
        except Exception:
            n = 0
        self.tray.set_state(True, n)

    def _to_tray(self):
        """Withdraw the window and keep serving autofill from the tray."""
        if self.tray is None or not self.tray.start():
            return False
        self._trayed = True
        self._tray_since = time.time()
        self._last_activity = time.time()
        self._tray_state()
        self.withdraw()
        # (the auto-lock tick has run since __init__ - nothing extra to start)
        return True

    def _show_from_tray(self):
        self._trayed = False
        # Re-assert: the window only exists while the vault is unlocked, so
        # anything that showed it means unlocked, and the icon/tooltip/menu
        # must agree even if some earlier path left them stale.
        self._tray_state()
        try:
            self.deiconify()
            self.lift()
            self.focus_force()
        except Exception:
            pass

    def _sys_events_tick(self):
        """Drain svlock.Monitor events (desktop lock / screensaver / suspend;
        they arrive on the monitor's thread) onto the Tk thread. The primary
        auto-lock trigger: fires for a VISIBLE window too - if the desktop
        locked, the user is not looking at it. Desktop unlock is never
        observed, so it can never unlock anything."""
        locked = False
        try:
            while True:
                evt = self._sys_events.get_nowait()
                import svconfig
                if (evt in (svlock.EVENT_DESKTOP_LOCK, svlock.EVENT_SUSPEND)
                        and svconfig.lock_on_desktop_lock() and not locked):
                    locked = True
                    self._lock_from_tray()
        except queue.Empty:
            pass
        except Exception:
            pass                            # teardown races
        if not locked:
            try:
                self.after(500, self._sys_events_tick)
            except Exception:
                pass

    def _autolock_tick(self):
        """FALLBACK auto-lock: TRUE system input idle (keyboard/mouse anywhere
        on the machine - XScreenSaverQueryInfo / GetLastInputInfo), never app
        interaction, so it cannot fire while the user works in another app
        (the 1.0.8 field defect). 0 = off (allowed; the desktop-lock trigger
        is primary). Only when NO system idle source exists at all does the
        old app-activity measure return, and then only for a trayed window."""
        import svconfig
        limit_min = svconfig.idle_lock_minutes()
        if limit_min > 0:
            idle = svlock.idle_ms()
            if idle is not None:
                if svlock.idle_exceeded(idle, limit_min):
                    self._lock_from_tray()
                    return
            elif self._trayed:
                # last resort (no X11/DBus/Win32 idle source): the pre-1.0.9
                # behaviour, so a background vault still can't stay unlocked
                # forever on a machine where idle can't be measured.
                idle_since = max(self._tray_since, self._last_activity)
                if time.time() - idle_since >= limit_min * 60:
                    self._lock_from_tray()
                    return
        try:
            self.after(30_000, self._autolock_tick)
        except Exception:
            pass

    def _lock_from_tray(self):
        """Lock while keeping the process (and tray icon) alive: stop the
        autofill server (socket/pipe + token gone), wipe scratch plaintext,
        drop the key material, and let main() park in the locked-tray loop."""
        self._locked_to_tray = True
        self._teardown_session()
        self.destroy()

    def _quit_from_tray(self):
        """Tray Quit = lock + exit, exactly the fail-closed close path."""
        self._locked_to_tray = False
        self._teardown_session()
        if self.tray is not None:
            self.tray.stop()
        self.destroy()

    def _teardown_session(self):
        if getattr(self, "_autofill", None):
            self._autofill.stop()          # tear down the pipe/socket + token
            self._autofill = None
        self.ws.wipe_all()
        try:
            self.vault.dek = None          # drop the data key reference
        except Exception:
            pass
        if self.tray is not None:
            self.tray.set_state(False)

    def destroy(self):
        """Every exit path (lock, quit, close, vault switch) funnels through
        Tk destroy - stop the system-lock monitor with the window so a
        LOCKED process never keeps DBus/message-pump watchers alive (there is
        nothing left for them to lock; the next unlock starts fresh ones)."""
        mon = getattr(self, "_sysmon", None)
        if mon is not None:
            self._sysmon = None
            try:
                mon.stop()
            except Exception:
                pass
        super().destroy()

    # ---------- shutdown
    def _on_close(self):
        ents = self.ws.list_open()
        if ents:
            changed = [e["name"] for e in ents if self.ws.changed(e["name"])]
            msg = (f"{len(ents)} file(s) are still decrypted outside the vault:\n\n  "
                   + "\n  ".join(e["name"] for e in ents))
            if changed:
                msg += ("\n\nUNSAVED EDITS in:\n  " + "\n  ".join(changed)
                        + "\n\nUse \"I'm done - close & wipe\" first if you want to keep them.")
            msg += "\n\nClosing now wipes every decrypted copy. Close anyway?"
            if not messagebox.askokcancel("SecureVault", msg):
                return
        # Vault is open: closing can either lock+exit, or keep running in the
        # background so browser autofill stays available. Honour the saved
        # choice; ask (once, with a remember box) when there is none.
        import svconfig
        choice = svconfig.on_close()
        can_tray = self.tray is not None and self.tray.available()
        if choice == "ask" and can_tray:
            dlg = _CloseChoiceDialog(self)
            self.wait_window(dlg)
            if dlg.result is None:
                return                      # cancelled - stay open
            choice = dlg.result
            if dlg.remember.get():
                svconfig.set_on_close(choice)
        if choice == "tray" and can_tray and self._to_tray():
            return
        if getattr(self, "_autofill", None):
            self._autofill.stop()          # tear down the pipe -> autofill stops
        self.ws.wipe_all()
        if self.tray is not None:
            self.tray.stop()
        self.destroy()


class _CloseChoiceDialog(tk.Toplevel):
    """Close with an unlocked vault: lock+exit, or keep serving from the tray.
    .result = "tray" | "exit" | None (cancel); .remember persists the choice."""

    def __init__(self, master):
        super().__init__(master)
        svtheme.ensure(self)
        self.title("SecureVault - close or keep running?")
        self.configure(bg=TH.bg)
        self.resizable(False, False)
        self.grab_set()
        self.result = None
        self.remember = tk.BooleanVar(value=False)
        ttk.Label(self, padding=(16, 14, 16, 4), justify="left", wraplength=420,
                  text="Keep SecureVault running in the background?").pack(anchor="w")
        ttk.Label(self, padding=(16, 0, 16, 10), justify="left", wraplength=420,
                  style="Muted.TLabel",
                  text="Running in the background keeps browser autofill "
                       "available while the window is closed (a tray icon "
                       "shows the state; it locks with your desktop and "
                       "after real keyboard/mouse inactivity - never while "
                       "you're working). Closing locks the vault and stops "
                       "autofill.").pack(anchor="w")
        ttk.Checkbutton(self, text="Remember my choice (change it later in "
                                   "Tools > Preferences)",
                        variable=self.remember).pack(anchor="w", padx=16)
        bar = ttk.Frame(self, padding=(16, 10, 16, 14)); bar.pack(fill="x")
        ttk.Button(bar, text="Run in background", style="Accent.TButton",
                   command=lambda: self._done("tray")).pack(side="left", padx=(0, 6))
        ttk.Button(bar, text="Close && lock",
                   command=lambda: self._done("exit")).pack(side="left", padx=(0, 6))
        ttk.Button(bar, text="Cancel", command=self._cancel).pack(side="right")
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.bind("<Escape>", lambda _e: self._cancel())

    def _done(self, what):
        self.result = what
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()


class PreferencesDialog(tk.Toplevel):
    """The two background-mode knobs. Deliberately small - everything else in
    the app is either a menu action or lives in the vault itself."""

    def __init__(self, master):
        super().__init__(master)
        svtheme.ensure(self)
        import svconfig
        self.title("SecureVault - Preferences")
        self.configure(bg=TH.bg)
        self.resizable(False, False)
        self.grab_set()
        ttk.Label(self, padding=(16, 12, 16, 4), font=(UI, 10, "bold"),
                  text="When I close the window with a vault open:").pack(anchor="w")
        self.close_var = tk.StringVar(value=svconfig.on_close())
        for val, label in (("ask", "Ask me each time"),
                           ("tray", "Keep running in the background (tray) - "
                                    "autofill stays available"),
                           ("exit", "Lock and exit")):
            ttk.Radiobutton(self, text=label, value=val,
                            variable=self.close_var).pack(anchor="w", padx=24)
        ttk.Label(self, padding=(16, 12, 16, 4), font=(UI, 10, "bold"),
                  text="Auto-lock:").pack(anchor="w")
        self.desklock = tk.BooleanVar(value=svconfig.lock_on_desktop_lock())
        ttk.Checkbutton(self, text="Lock when the desktop locks or the "
                                   "screensaver starts (also before sleep)",
                        variable=self.desklock).pack(anchor="w", padx=24)
        idle_now = svconfig.idle_lock_minutes()
        self.idle_on = tk.BooleanVar(value=idle_now > 0)
        row = ttk.Frame(self, padding=(24, 2, 16, 0)); row.pack(anchor="w")
        ttk.Checkbutton(row, text="Also lock after",
                        variable=self.idle_on).pack(side="left")
        self.mins = tk.IntVar(
            value=idle_now if idle_now > 0 else svconfig.DEFAULT_IDLE_MIN)
        ttk.Spinbox(row, from_=svconfig.IDLE_MIN, to=svconfig.IDLE_MAX,
                    textvariable=self.mins, width=5).pack(side="left", padx=6)
        ttk.Label(row, text="minutes without keyboard/mouse input").pack(side="left")
        ttk.Label(self, padding=(24, 2, 16, 0), style="Muted.TLabel",
                  wraplength=420, justify="left",
                  text="Idle means no keyboard or mouse input anywhere on "
                       "this computer - working in other apps counts as "
                       "activity, so the vault never locks mid-work. "
                       "Unlocking the desktop never unlocks the vault.").pack(anchor="w")
        ttk.Label(self, padding=(16, 12, 16, 4), font=(UI, 10, "bold"),
                  text="Startup:").pack(anchor="w")
        import svautostart
        self.autostart = tk.BooleanVar(
            value=bool(svconfig.autostart_pref()) or svautostart.is_enabled())
        ttk.Checkbutton(self, text="Start SecureVault at login - locked, in "
                                   "the tray (autofill is one unlock away)",
                        variable=self.autostart).pack(anchor="w", padx=24)
        bar = ttk.Frame(self, padding=(16, 12, 16, 14)); bar.pack(fill="x")
        ttk.Button(bar, text="Save", style="Accent.TButton",
                   command=self._save).pack(side="left")
        ttk.Button(bar, text="Cancel", command=self.destroy).pack(side="right")
        self.bind("<Escape>", lambda _e: self.destroy())

    def _save(self):
        import svconfig, svautostart
        svconfig.set_on_close(self.close_var.get())
        svconfig.set_lock_on_desktop_lock(self.desklock.get())
        try:
            mins = max(svconfig.IDLE_MIN, min(svconfig.IDLE_MAX,
                                              int(self.mins.get())))
        except (ValueError, tk.TclError):
            mins = svconfig.DEFAULT_IDLE_MIN
        svconfig.set_idle_lock_minutes(mins if self.idle_on.get() else 0)
        if not self.desklock.get() and not self.idle_on.get():
            # both triggers off: legal, but never silently
            messagebox.showwarning(
                "SecureVault - auto-lock is OFF",
                "You have turned off BOTH auto-lock triggers.\n\n"
                "An unlocked vault (including one running in the tray) will "
                "now stay unlocked indefinitely - until you lock it yourself "
                "or quit. Anyone at this desk can read it and use autofill.\n\n"
                "Recommended: keep at least 'Lock when the desktop locks' "
                "enabled.", parent=self)
        svconfig.set_autostart(self.autostart.get())
        svautostart.apply_pref(self.autostart.get())
        self.destroy()


class VaultChooser(tk.Toplevel):
    r"""Small first-run chooser: create a new vault or open an existing one, with
    quick access to recently used ones. Returns .result as (mode, path) where mode
    is 'new' or 'open', or None if cancelled. Paths only - never a secret."""
    def __init__(self, master, default_new=None, recent=None):
        super().__init__(master)
        svtheme.ensure(self)
        self.title("SecureVault - choose a vault")
        self.configure(bg=TH.bg)
        self.result = None
        self.default_new = default_new
        self.resizable(False, False)
        self.grab_set()
        ttk.Label(self, padding=(14, 14, 14, 6), justify="left",
                  text="No vault is open yet.\n\nCreate a new encrypted vault, or "
                       "open an existing SecureVault.dat.").pack(anchor="w")
        btns = ttk.Frame(self, padding=(14, 0, 14, 8)); btns.pack(fill="x")
        ttk.Button(btns, text="Create new vault...", command=self._new).pack(side="left", padx=3)
        ttk.Button(btns, text="Open existing vault...", command=self._open).pack(side="left", padx=3)
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side="right", padx=3)
        live = [p for p in (recent or []) if os.path.isfile(p)]
        if live:
            ttk.Separator(self, orient="horizontal").pack(fill="x", padx=14, pady=4)
            ttk.Label(self, padding=(14, 0, 14, 0), text="Recent vaults:").pack(anchor="w")
            lst = ttk.Frame(self, padding=(14, 2, 14, 12)); lst.pack(fill="x")
            for p in live[:6]:
                ttk.Button(lst, text=p, command=lambda pp=p: self._recent(pp))\
                    .pack(anchor="w", fill="x", pady=1)
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.bind("<Escape>", lambda _e: self._cancel())

    _FILTER = [("SecureVault container", "*.dat"), ("All files", "*.*")]

    def _new(self):
        initdir = os.path.dirname(self.default_new) if self.default_new else None
        path = filedialog.asksaveasfilename(
            parent=self, title="Create new vault", defaultextension=".dat",
            initialfile=os.path.basename(self.default_new or "SecureVault.dat"),
            initialdir=initdir, filetypes=self._FILTER)
        if path:
            self.result = ("new", path); self.destroy()

    def _open(self):
        path = filedialog.askopenfilename(parent=self, title="Open vault",
                                          filetypes=self._FILTER)
        if path:
            self.result = ("open", path); self.destroy()

    def _recent(self, p):
        self.result = ("open", p); self.destroy()

    def _cancel(self):
        self.result = None; self.destroy()


def _create_vault_at(master, path):
    r"""Create + enroll a fresh vault at `path` (dialogs parented to `master`).
    Returns an unlocked Vault, or None if cancelled. Marks the vault so the App
    can offer the autofill wizard once, and remembers the path (paths only)."""
    if os.path.isfile(path):
        messagebox.showerror("SecureVault", f"A file already exists:\n{path}")
        return None
    creds = gui_prompt_credentials(confirm=True, need_totp=False, title="Create SecureVault")
    if not creds:
        return None
    vault = sv.Vault(path)
    try:
        secret = vault.create(sv.auth_material(creds[0].encode("utf-8"),
                                               creds[1].encode("utf-8")))
    except sv.VaultError as ex:
        messagebox.showerror("SecureVault", str(ex)); return None
    import svtotp
    uri = svtotp.provisioning_uri(secret, account="SecureVault")
    _show_secret_window(master, secret, uri)
    sv.remember_vault(path)
    try:
        vault._sv_freshly_created = True
    except Exception:
        pass
    return vault


def _unlock_vault_at(master, path):
    """Unlock an existing vault at `path` (up to 3 tries). Returns an unlocked
    Vault or None. Remembers the path on success (paths only, never secrets)."""
    vault = sv.Vault(path)
    if not vault.exists():
        messagebox.showerror("SecureVault", f"No vault found at:\n{path}")
        return None
    for _ in range(3):
        creds = gui_prompt_credentials(confirm=False, need_totp=True)
        if creds is None:
            return None
        try:
            vault.unlock(sv.auth_material(creds[0].encode("utf-8"),
                                          creds[1].encode("utf-8")), creds[2])
            sv.remember_vault(path)
            return vault
        except sv.VaultError as ex:
            messagebox.showerror("SecureVault", str(ex))
    return None


def main(start_locked=False):
    import atexit, svipc, svtray

    # Single-instance: if SecureVault is already running (window, tray, or
    # locked-in-tray), poke it awake and leave. Launching from the menu is the
    # guaranteed way back to a background instance even if the tray is hidden.
    if svipc.activate_running():
        return

    # presence marker (pid only, nothing secret): lets the browser extension
    # distinguish "SecureVault isn't running" from "running but locked"
    try:
        svipc.presence_write()
        atexit.register(svipc.presence_clear)
    except Exception:
        pass

    # tray + activation exist for the whole process life; activation pokes are
    # routed through the tray event queue, which every state already drains.
    tray = svtray.Tray()
    act = svipc.ActivationServer(lambda: tray.events.put("show"))
    act.start()
    atexit.register(act.stop)

    # --locked (autostart at login): no window, no prompt - just the locked
    # tray icon and the activation listener. Never on a machine with no vault.
    if start_locked:
        dat = sv.resolve_dat(remember=False)
        if not os.path.isfile(dat):
            return
        tray.start()
        vault = _locked_tray_loop(tray, dat)
        while vault is not None:
            app = App(vault, tray=tray)
            app.mainloop()
            nxt = getattr(app, "_next_vault", None)
            if nxt is not None:
                vault = nxt
                continue
            if getattr(app, "_locked_to_tray", False):
                vault = _locked_tray_loop(tray, app.vault.path)
                continue
            break
        tray.stop()
        return

    root = tk.Tk(); root.withdraw()
    # Aura before the FIRST window of the session. Everything from here on -
    # the keylogger warning, the vault chooser, the unlock prompts and the PIN
    # pad - is drawn before App() exists, so waiting until then would show the
    # user a stack of default-grey dialogs and only then a themed window.
    svtheme.apply(root, svtheme.load_pref())

    # best-effort keystroke-logging check before any secret is entered. The PIN
    # is click-entered regardless, so a keylogger cannot capture it either way.
    warns = svsec.scan()
    if warns:
        messagebox.showwarning(
            "SecureVault - security warning",
            "Possible monitoring / keylogging detected:\n\n  - "
            + "\n  - ".join(warns)
            + "\n\nDetection is heuristic. Your 6-digit PIN is entered by mouse "
              "clicks on a randomized pad, so it is safe from keyloggers even so.")

    # Startup vault: reopen the remembered one if it still exists; otherwise a
    # legacy default next to the exe; otherwise let the user choose/create.
    dat = sv.resolve_dat(remember=False)
    if os.path.isfile(dat):
        vault = _unlock_vault_at(root, dat)
    else:
        import svconfig
        chooser = VaultChooser(root, default_new=dat, recent=svconfig.recent_vaults())
        root.wait_window(chooser)
        if not chooser.result:
            root.destroy(); return
        mode, path = chooser.result
        vault = _create_vault_at(root, path) if mode == "new" else _unlock_vault_at(root, path)
    root.destroy()

    # Run; if the user switches vaults from the File menu, App sets _next_vault
    # and closes, and we reopen a clean window on the new (already-unlocked) one.
    # A lock from the tray parks the process in _locked_tray_loop (icon stays,
    # keys gone) until the user unlocks again or quits.
    while vault is not None:
        app = App(vault, tray=tray)
        app.mainloop()
        nxt = getattr(app, "_next_vault", None)
        if nxt is not None:
            vault = nxt
            continue
        if getattr(app, "_locked_to_tray", False):
            vault = _locked_tray_loop(tray, app.vault.path)
            continue
        break
    tray.stop()


def _locked_tray_loop(tray, dat_path):
    """The process while LOCKED in the tray: no keys, no autofill server, just
    an icon waiting for 'Open' (-> full three-factor unlock) or 'Quit' - plus
    the activation listener, so launching the app again also lands here as a
    'show'. Returns an unlocked Vault to reopen the window on, or None."""
    tray.start()                            # idempotent; needed for --locked boots
    tray.set_state(False)
    root = tk.Tk(); root.withdraw()
    svtheme.apply(root, svtheme.load_pref())
    result = {"vault": None}

    def poll():
        try:
            while True:
                evt = tray.events.get_nowait()
                if evt == "quit":
                    root.quit(); return
                if evt == "show":
                    v = _unlock_vault_at(root, dat_path)
                    if v is not None:
                        result["vault"] = v
                        root.quit(); return
        except Exception:
            pass                            # queue.Empty
        root.after(250, poll)

    poll()
    root.mainloop()
    try:
        root.destroy()
    except Exception:
        pass
    return result["vault"]


def _show_secret_window(master, secret, uri):
    r"""Show the TOTP enrollment once: a scannable QR code (preferred) plus the
    secret and otpauth URI as text for manual entry."""
    win = tk.Toplevel(master); win.title("SecureVault - enroll authenticator")
    svtheme.ensure(win)
    win.configure(bg=TH.bg)
    win.grab_set()
    ttk.Label(win, padding=(10, 10, 10, 4), justify="left",
              text="Scan this with your authenticator app (shown once):").pack(anchor="w")

    import svqr
    qr_img = svqr.photoimage(uri, scale=6)
    if qr_img is not None:
        qr_label = ttk.Label(win, image=qr_img)
        qr_label.image = qr_img          # keep a reference or Tk drops the image
        qr_label.pack(padx=10, pady=4)
    else:
        ttk.Label(win, padding=(10, 0), foreground=TH.warn, justify="left",
                  text="(QR unavailable - enter the secret below manually.)").pack(anchor="w")

    ttk.Label(win, padding=(10, 4, 10, 0), justify="left",
              text=f"Or enter it by hand -  Secret:  {secret}").pack(anchor="w")
    txt = svtheme.text(win, height=3, width=64, wrap="char")
    txt.insert("1.0", uri)
    txt.configure(state="disabled"); txt.pack(padx=10, pady=6)
    ttk.Label(win, padding=10, justify="left",
              text="Google Authenticator / Authy / Aegis / 1Password all work.\n"
                   "You will need a code from it every time you open the vault.").pack(anchor="w")
    ttk.Button(win, text="I've saved it", command=win.destroy).pack(pady=8)
    master.wait_window(win)


if __name__ == "__main__":
    main()
