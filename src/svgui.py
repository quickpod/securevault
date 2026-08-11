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
import os, sys, threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import securevault as sv
import svsec
import svopen
import svshell


PIN_LEN = 6

# Treeview iid prefixes. A row is either a folder or a file and the id says
# which, so a click never has to guess from the text.
DIR_TAG  = "D\x00"
FILE_TAG = "F\x00"


class NumericPinPad(tk.Toplevel):
    r"""Randomized on-screen numeric keypad for the 6-digit PIN. Digits are
    entered with MOUSE CLICKS on a shuffled 0-9 pad, and the pad reshuffles after
    every click - so a keylogger sees no keystrokes and a mouse-position logger
    sees positions that map to different digits each time. Returns .result (str)
    or None if cancelled."""
    def __init__(self, master, prompt="Enter 6-digit PIN"):
        super().__init__(master)
        self.title("SecureVault - PIN")
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
            tk.Button(self.pad, text=d, width=4, height=2,
                      command=lambda c=d: self._press(c)).grid(
                      row=idx // 5, column=idx % 5, padx=2, pady=2)

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
    def __init__(self, vault):
        super().__init__()
        self.vault = vault
        self.ws = svopen.Workspace(vault)
        self.cwd = ""                      # folder currently shown, "" = root
        self.index = {}
        self.fmap = {"": {"dirs": set(), "files": []}}
        self._statcache = {}
        self.title("SecureVault — by QuickOpen (quickopen.ai)")
        self.geometry("1040x620")
        self.minsize(760, 420)
        self._set_window_icon()
        self._build()
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

        top = ttk.Frame(self, padding=(8, 8, 8, 4)); top.pack(fill="x")
        ttk.Label(top, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh())
        e = ttk.Entry(top, textvariable=self.search_var); e.pack(side="left", fill="x", expand=True, padx=6)
        e.focus_set()
        ttk.Button(top, text="Add Files", command=self.add_files).pack(side="left", padx=2)
        ttk.Button(top, text="Add Folder", command=self.add_folder).pack(side="left", padx=2)
        ttk.Button(top, text="Passwords", command=self.open_passwords).pack(side="left", padx=2)

        self.pan = ttk.PanedWindow(self, orient="horizontal")
        self.pan.pack(fill="both", expand=True, padx=8)

        # --- left: folder tree
        left = ttk.Frame(self.pan)
        ttk.Label(left, text="Folders", anchor="w", padding=(2, 0, 0, 3)).pack(fill="x")
        self.folders = ttk.Treeview(left, show="tree", selectmode="browse")
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
        ttk.Label(nav, textvariable=self.path_var, relief="groove", anchor="w",
                  padding=3).pack(side="left", fill="x", expand=True, padx=6)

        cols = ("name", "size", "type", "modified", "source")
        self.tree = ttk.Treeview(right, columns=cols, show="headings", selectmode="extended")
        for c, w in (("name", 320), ("size", 85), ("type", 90), ("modified", 125), ("source", 230)):
            self.tree.heading(c, text=c.title(), command=lambda cc=c: self.sort_by(cc))
            self.tree.column(c, width=w, anchor="w")
        rvs = ttk.Scrollbar(right, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=rvs.set)
        rvs.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-1>", self._on_row_activate)
        self.tree.bind("<Return>", self._on_row_activate)
        self.tree.bind("<BackSpace>", lambda e: self.go_up())
        self.tree.tag_configure("dir", font=("Segoe UI", 9, "bold"))
        self.pan.add(right, weight=4)

        # --- checked-out files (packed only while something is open)
        self.openbar = ttk.Frame(self, padding=(8, 4))
        self.open_var = tk.StringVar(value="")
        ttk.Label(self.openbar, textvariable=self.open_var, anchor="w",
                  foreground="#8a4b00").pack(side="left", fill="x", expand=True)
        ttk.Button(self.openbar, text="I'm done - close & wipe",
                   command=self.finish_open).pack(side="right", padx=3)

        self.bottombar = ttk.Frame(self, padding=8); self.bottombar.pack(fill="x")
        for txt, cmd in (("Open", self.open_external), ("Preview", self.preview),
                         ("Extract Selected", self.extract_sel), ("Extract All", self.extract_all),
                         ("Delete", self.delete_sel), ("Verify", self.verify),
                         ("Change Password", self.change_pw)):
            ttk.Button(self.bottombar, text=txt, command=cmd).pack(side="left", padx=3)

        self.status = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w").pack(fill="x", side="bottom")
        self._sort = ("name", False)

    def _menubar(self):
        bar = tk.Menu(self)
        tools = tk.Menu(bar, tearoff=0)
        tools.add_command(label="Install / repoint Explorer right-click menu",
                          command=self.shell_register)
        tools.add_command(label="Remove Explorer right-click menu", command=self.shell_unregister)
        tools.add_command(label="Explorer menu status...", command=self.shell_status)
        tools.add_separator()
        tools.add_command(label="Verify integrity", command=self.verify)
        tools.add_command(label="Vault info...", command=self.vault_info)
        tools.add_command(label="Change password / PIN", command=self.change_pw)
        tools.add_separator()
        tools.add_command(label="Passwords (manager)...", command=self.open_passwords)
        bar.add_cascade(label="Tools", menu=tools)
        self.configure(menu=bar)

    def _sash(self):
        try:
            self.pan.sashpos(0, 250)
        except Exception:
            pass

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
        ext = os.path.splitext(name)[1].lower()
        if ext in (".png", ".gif", ".ppm", ".pgm"):
            try:
                img = tk.PhotoImage(data=data)
                lbl = tk.Label(win, image=img); lbl.image = img; lbl.pack(expand=True)
                return
            except Exception:
                pass
        txt = tk.Text(win, wrap="none")
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
            messagebox.showerror("SecureVault", f"Could not install the Explorer menu:\n{ex}")
            return
        messagebox.showinfo("SecureVault",
            "Explorer right-click menu installed for your user account.\n\n"
            "  Right-click a file    -> Send to SV (Secure Vault)\n"
            "  Right-click a folder  -> Send folder to SV\n"
            "  Right-click a backdrop-> Open Secure Vault\n\n"
            f"Pointing at:\n{exe}")
        self.status.set("Explorer menu installed")

    def shell_unregister(self):
        try:
            svshell.unregister()
        except Exception as ex:
            messagebox.showerror("SecureVault", str(ex)); return
        messagebox.showinfo("SecureVault", "Explorer right-click menu removed.")

    def shell_status(self):
        messagebox.showinfo("SecureVault - Explorer menu", svshell.status_text())

    def _shell_hint(self):
        """Mention a missing or stale menu once in the status bar. No dialog -
        the registry is only ever touched when you ask for it."""
        try:
            installed, _cmd = svshell.is_registered()
            current = svshell.is_current()
        except Exception:
            return
        if not installed:
            self.status.set("Tip: Tools > Install Explorer right-click menu "
                            "to get 'Send to SV' back.")
        elif not current:
            self.status.set("Tip: the Explorer menu points at a different copy of "
                            "SecureVault - Tools > Install / repoint to fix it.")

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
        if getattr(self, "_autofill", None):
            self._autofill.stop()          # tear down the pipe -> autofill stops
        self.ws.wipe_all()
        self.destroy()


def main():
    dat = sv.default_dat()
    root = tk.Tk(); root.withdraw()

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

    vault = sv.Vault(dat)
    if not vault.exists():
        if not messagebox.askyesno("SecureVault",
                f"No vault found at:\n{dat}\n\nCreate a new Secure Vault here?"):
            return
        creds = gui_prompt_credentials(confirm=True, need_totp=False, title="Create SecureVault")
        if not creds: return
        secret = vault.create(sv.auth_material(creds[0].encode("utf-8"), creds[1].encode("utf-8")))
        import svtotp
        uri = svtotp.provisioning_uri(secret, account="SecureVault")
        _show_secret_window(root, secret, uri)
    else:
        for _ in range(3):
            creds = gui_prompt_credentials(confirm=False, need_totp=True)
            if creds is None:
                return
            try:
                vault.unlock(sv.auth_material(creds[0].encode("utf-8"),
                                              creds[1].encode("utf-8")), creds[2]); break
            except sv.VaultError as ex:
                messagebox.showerror("SecureVault", str(ex))
        else:
            return
    root.destroy()
    App(vault).mainloop()


def _show_secret_window(master, secret, uri):
    r"""Show the TOTP enrollment secret once, with a QR code if 'qrcode' is
    available, else the otpauth URI as text."""
    win = tk.Toplevel(master); win.title("SecureVault - enroll authenticator")
    win.grab_set()
    ttk.Label(win, padding=10, justify="left",
              text="Add this to your authenticator app NOW (shown once):\n\n"
                   f"Secret:  {secret}").pack(anchor="w")
    txt = tk.Text(win, height=3, width=64, wrap="char"); txt.insert("1.0", uri)
    txt.configure(state="disabled"); txt.pack(padx=10, pady=6)
    ttk.Label(win, padding=10,
              text="Google Authenticator / Authy / Aegis / 1Password all work.\n"
                   "You will need a code from it every time you open the vault.").pack(anchor="w")
    ttk.Button(win, text="I've saved it", command=win.destroy).pack(pady=8)
    master.wait_window(win)


if __name__ == "__main__":
    main()
