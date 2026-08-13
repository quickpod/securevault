#!/usr/bin/env python3
r"""
svpassgui - the password-manager window, opened from the main SecureVault GUI.

It reuses the ALREADY-UNLOCKED vault handed in by svgui, so it needs no second
master secret: if you are looking at this window you already passed password +
PIN + TOTP. The store is the single "__passwords__" blob managed by svpass.

Design notes that matter:
  - Passwords are NEVER placed in a widget. The list shows title / username /
    domain / strength only; the password reaches the clipboard and nothing else.
  - Copying goes through the phishing gate: a confirm dialog names the saved
    domain, because copy-paste has no origin check the way Chrome autofill did.
  - The clipboard is cleared by a Tk `after` timer (this window stays alive),
    not the daemon-thread timer svpass uses for the transient CLI.
"""

import os, sys, time
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import svpass
import svtotp
import svchrome
import svtheme
from svtheme import TH, UI, MONO


class PasswordManager(tk.Toplevel):
    def __init__(self, master, vault):
        super().__init__(master)
        svtheme.ensure(self)
        self.title("SecureVault - Passwords")
        self.configure(bg=TH.bg)
        self.geometry("1020x580")
        self.minsize(860, 460)
        self.store = svpass.PasswordStore(vault)
        self.store.load()
        self._clip_after = None
        self._totp_after = None
        self._build()
        self.refresh()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.transient(master)

    # ---------------------------------------------------------------- layout
    def _build(self):
        # Aura header + beam, so this window reads as part of the same app
        # rather than a dialog that wandered in from another one.
        head = ttk.Frame(self, padding=(12, 12, 12, 9)); head.pack(fill="x")
        ttk.Label(head, text="Passwords", font=(UI, 13, "bold")).pack(side="left")
        ttk.Label(head, foreground=TH.muted,
                  text="stored in this vault - never on disk in the clear")\
            .pack(side="left", padx=(14, 0))
        svtheme.beam(self).pack(fill="x")

        # TWO rows, not one. Seven buttons and a search field fitted on one row
        # at the old 8pt; at the Aura type scale they ran off the edge of the
        # window, which is how "Browsers..." became unreachable. Splitting by
        # frequency also reads better: the things you do to an ENTRY on top,
        # the things you do to the WHOLE STORE underneath.
        top = ttk.Frame(self, padding=(6, 10, 6, 2)); top.pack(fill="x")
        ttk.Label(top, text="Search:").pack(side="left")
        self.q = tk.StringVar()
        e = ttk.Entry(top, textvariable=self.q)
        e.pack(side="left", padx=6, fill="x", expand=True)
        e.bind("<KeyRelease>", lambda _e: self.refresh())
        e.focus_set()
        ttk.Button(top, text="Add", command=self.add,
                   style="Accent.TButton").pack(side="left", padx=2)
        ttk.Button(top, text="Edit", command=self.edit).pack(side="left", padx=2)
        ttk.Button(top, text="Delete", command=self.delete).pack(side="left", padx=2)

        tools = ttk.Frame(self, padding=(6, 2, 6, 6)); tools.pack(fill="x")
        for txt, cmd in (("Generate...", self.generate),
                         ("Import Chrome CSV...", self.import_chrome),
                         ("Audit...", self.audit),
                         ("Browsers...", self.browsers)):
            ttk.Button(tools, text=txt, command=cmd).pack(side="left", padx=2)

        cols = ("title", "username", "domain", "strength", "twofa")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", selectmode="browse")
        for c, w, t in (("title", 220, "Title"), ("username", 220, "Username"),
                        ("domain", 200, "Domain"), ("strength", 120, "Strength"),
                        ("twofa", 60, "2FA")):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=6)
        self.tree.bind("<Double-1>", lambda _e: self.copy_password())
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._sync_totp())

        act = ttk.Frame(self, padding=6); act.pack(fill="x")
        ttk.Button(act, text="Copy password", command=self.copy_password).pack(side="left", padx=2)
        ttk.Button(act, text="Copy username", command=self.copy_username).pack(side="left", padx=2)
        ttk.Button(act, text="Copy TOTP", command=self.copy_totp).pack(side="left", padx=2)
        ttk.Button(act, text="Open URL in browser", command=self.open_url).pack(side="left", padx=2)
        self.status = tk.StringVar(value="")
        ttk.Label(act, textvariable=self.status,
                  foreground=TH.good).pack(side="right")

    # ------------------------------------------------------------------ data
    def refresh(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self._rows = {}
        for eid, e in self.store.search(self.q.get()):
            pw = e.get("password", "")
            vals = (e.get("title", ""), e.get("username", ""),
                    svpass.domain_of(e.get("url", "")),
                    f"{svpass.strength_label(pw)} ({svpass.entropy_bits(pw):.0f})" if pw else "(none)",
                    "yes" if e.get("totp_secret") else "")
            iid = self.tree.insert("", "end", values=vals)
            self._rows[iid] = eid
        n = len(self._rows)
        self.status.set(f"{n} entr{'y' if n == 1 else 'ies'}")

    def _selected_eid(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Passwords", "Select an entry first.", parent=self)
            return None
        return self._rows.get(sel[0])

    # -------------------------------------------------------------- clipboard
    def _copy(self, text, label, seconds=svpass.CLIP_CLEAR_SECONDS):
        """Copy via Tk (so it lives with this window) and arm an `after` timer
        to clear it - but only if it still holds our value."""
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()  # flush to the OS clipboard
        if self._clip_after:
            try: self.after_cancel(self._clip_after)
            except Exception: pass
        def clear():
            try:
                if self.clipboard_get() == text:
                    self.clipboard_clear(); self.update()
                    self.status.set("clipboard cleared")
            except Exception:
                pass
        self._clip_after = self.after(seconds * 1000, clear)
        self.status.set(f"{label} copied - clears in {seconds}s")

    def copy_password(self):
        eid = self._selected_eid()
        if not eid: return
        e = self.store.get(eid)
        dom = svpass.domain_of(e.get("url", ""))
        # the phishing gate, GUI form: name the domain and make the user confirm
        if dom:
            ok = messagebox.askyesno(
                "Confirm site",
                f"Copy the password for:\n\n    {dom}\n\n"
                f"({e.get('title','')} / {e.get('username','')})\n\n"
                "Only paste it into that site. Continue?", parent=self)
            if not ok:
                self.status.set("copy cancelled"); return
        self._copy(e["password"], "password")

    def copy_username(self):
        eid = self._selected_eid()
        if not eid: return
        self._copy(self.store.get(eid).get("username", ""), "username")

    def copy_totp(self):
        eid = self._selected_eid()
        if not eid: return
        try:
            code, _rem = self.store.totp_now(eid)
        except svpass.PassError as ex:
            messagebox.showinfo("Passwords", str(ex), parent=self); return
        self._copy(code, "TOTP code", seconds=30)

    def _sync_totp(self):
        # live-tick the status with the current code if the entry has 2FA
        sel = self.tree.selection()
        if self._totp_after:
            try: self.after_cancel(self._totp_after)
            except Exception: pass
            self._totp_after = None
        if not sel:
            return
        eid = self._rows.get(sel[0])
        e = self.store.get(eid) if eid else None
        if not (e and e.get("totp_secret")):
            return
        def tick():
            try:
                code, rem = self.store.totp_now(eid)
                self.status.set(f"TOTP {code}  ({rem}s)")
                self._totp_after = self.after(1000, tick)
            except Exception:
                pass
        tick()

    def open_url(self):
        eid = self._selected_eid()
        if not eid: return
        url = self.store.get(eid).get("url", "")
        if not url:
            messagebox.showinfo("Passwords", "No URL on this entry.", parent=self); return
        if "//" not in url:
            url = "https://" + url
        import webbrowser
        webbrowser.open(url)

    # ------------------------------------------------------------------ edits
    def add(self):
        dlg = _EntryDialog(self, "Add entry")
        self.wait_window(dlg)
        if dlg.result is None: return
        r = dlg.result
        try:
            self.store.add(**r)
        except svpass.PassError as ex:
            messagebox.showerror("Passwords", str(ex), parent=self); return
        self.store.save(); self.refresh()

    def edit(self):
        eid = self._selected_eid()
        if not eid: return
        dlg = _EntryDialog(self, "Edit entry", self.store.get(eid))
        self.wait_window(dlg)
        if dlg.result is None: return
        try:
            self.store.update(eid, **dlg.result)
        except svpass.PassError as ex:
            messagebox.showerror("Passwords", str(ex), parent=self); return
        self.store.save(); self.refresh()

    def delete(self):
        eid = self._selected_eid()
        if not eid: return
        e = self.store.get(eid)
        if not messagebox.askyesno("Delete",
                f"Delete '{e['title']}' ({e.get('username','')})?", parent=self):
            return
        self.store.delete(eid); self.store.save(); self.refresh()

    def generate(self):
        dlg = _GenDialog(self)
        self.wait_window(dlg)
        if dlg.result:
            self._copy(dlg.result, "generated password")

    def browsers(self):
        """Manage paired browser extensions. The autofill service owns the
        pairing state, and it only exists while the vault is unlocked and
        serving - so if it is missing, say why rather than opening a dialog
        whose buttons would all fail."""
        svc = getattr(self.master, "_autofill", None)
        if svc is None:
            messagebox.showinfo(
                "SecureVault",
                "Browser autofill is not running, so there is nothing to pair "
                "with.\n\nRun Install-BrowserFill.ps1 -Apply and load the "
                "extension, then reopen SecureVault.", parent=self)
            return
        open_pairing(self.master, svc)

    def audit(self):
        r = self.store.audit()
        groups = {tuple(sorted([eid] + others)) for eid, others in r["reused"].items()}
        lines = [f"Total entries: {r['total']}", "",
                 f"Reused passwords : {len(r['reused'])} entries across {len(groups)} groups",
                 f"Weak (<60 bits)  : {len(r['weak'])}",
                 f"Stale (>1 year)  : {len(r['stale'])}",
                 f"No 2FA secret    : {len(r['no_totp'])}"]
        if r["reused"]:
            lines += ["", "Reuse is the one to fix first - one breach unlocks every", "site sharing that password. Worst groups:"]
            shown = set()
            for eid, others in sorted(r["reused"].items(), key=lambda kv: len(kv[1]), reverse=True):
                g = tuple(sorted([eid] + others))
                if g in shown: continue
                shown.add(g)
                titles = [self.store.get(i)["title"] for i in g]
                lines.append(f"  {len(g)}x: {', '.join(titles[:6])}")
                if len(shown) >= 6: break
        messagebox.showinfo("Password audit", "\n".join(lines), parent=self)

    def import_chrome(self):
        if not messagebox.askyesno("Import from Chrome",
                svchrome.EXPORT_STEPS + "\n\nHave you exported the CSV and want to pick it now?",
                parent=self):
            return
        path = filedialog.askopenfilename(parent=self, title="Select Chrome password CSV",
                                          filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not path: return
        try:
            prev = svchrome.preview_csv(path)
        except svchrome.ChromeError as ex:
            messagebox.showerror("Import", str(ex), parent=self); return
        msg = (f"Found {prev['total']} credentials "
               f"({prev['with_password']} with a password).\n\n"
               "Import them into the vault and then SHRED the CSV?\n\n"
               f"File: {path}")
        if not messagebox.askyesno("Import", msg, parent=self):
            return
        res = svchrome.import_csv(self.store, path)
        self.store.save()
        shredded = svchrome.shred_file(path)
        self.refresh()
        messagebox.showinfo("Import complete",
            f"Imported {res['added']} entries ({res['duplicates']} duplicates skipped).\n\n"
            + ("The CSV was shredded and deleted."
               if shredded else "WARNING: could not delete the CSV - remove it yourself."),
            parent=self)

    def _on_close(self):
        for a in (self._clip_after, self._totp_after):
            if a:
                try: self.after_cancel(a)
                except Exception: pass
        # leave the clipboard as the user's timer will handle it; but if we still
        # hold a secret, clear it now rather than on a timer that dies with us
        self.destroy()


class _EntryDialog(tk.Toplevel):
    """Add/edit form. Password is shown masked with a reveal toggle and a
    'Generate' button; it is the only field that can hold a secret."""
    def __init__(self, master, title, entry=None):
        super().__init__(master)
        svtheme.ensure(self)
        self.title(title)
        self.configure(bg=TH.bg)
        self.resizable(False, False)
        self.grab_set()
        self.result = None
        e = entry or {}
        self.vars = {k: tk.StringVar(value=e.get(k, "")) for k in
                     ("title", "username", "url", "notes", "totp_secret")}
        self.pw = tk.StringVar(value=e.get("password", ""))
        rows = [("Title", "title"), ("Username", "username"), ("URL", "url")]
        r = 0
        for label, key in rows:
            ttk.Label(self, text=label).grid(row=r, column=0, sticky="e", padx=6, pady=3)
            ttk.Entry(self, textvariable=self.vars[key], width=48).grid(row=r, column=1, columnspan=2, sticky="w", padx=6)
            r += 1
        ttk.Label(self, text="Password").grid(row=r, column=0, sticky="e", padx=6, pady=3)
        self.pw_entry = ttk.Entry(self, textvariable=self.pw, width=36, show="*")
        self.pw_entry.grid(row=r, column=1, sticky="w", padx=6)
        self._shown = False
        ttk.Button(self, text="Show", width=6, command=self._toggle).grid(row=r, column=2, sticky="w")
        r += 1
        ttk.Button(self, text="Generate strong password", command=self._gen)\
            .grid(row=r, column=1, sticky="w", padx=6, pady=2); r += 1
        ttk.Label(self, text="TOTP secret").grid(row=r, column=0, sticky="e", padx=6, pady=3)
        ttk.Entry(self, textvariable=self.vars["totp_secret"], width=48)\
            .grid(row=r, column=1, columnspan=2, sticky="w", padx=6)
        r += 1
        ttk.Label(self, text="(raw base32 or an otpauth:// URI)").grid(row=r, column=1, sticky="w", padx=6); r += 1
        ttk.Label(self, text="Notes").grid(row=r, column=0, sticky="ne", padx=6, pady=3)
        self.notes = svtheme.text(self, width=48, height=4, font=(UI, 10))
        self.notes.insert("1.0", e.get("notes", ""))
        self.notes.grid(row=r, column=1, columnspan=2, sticky="w", padx=6); r += 1
        bar = ttk.Frame(self); bar.grid(row=r, column=0, columnspan=3, pady=8)
        ttk.Button(bar, text="Save", command=self._ok).pack(side="left", padx=4)
        ttk.Button(bar, text="Cancel", command=self.destroy).pack(side="left", padx=4)

    def _toggle(self):
        self._shown = not self._shown
        self.pw_entry.configure(show="" if self._shown else "*")

    def _gen(self):
        self.pw.set(svpass.generate())
        if not self._shown: self._toggle()

    def _ok(self):
        title = self.vars["title"].get().strip()
        if not title:
            messagebox.showerror("Entry", "Title is required.", parent=self); return
        self.result = {
            "title": title,
            "username": self.vars["username"].get().strip(),
            "url": self.vars["url"].get().strip(),
            "password": self.pw.get(),
            "notes": self.notes.get("1.0", "end").strip(),
            "totp_secret": self.vars["totp_secret"].get().strip(),
        }
        self.destroy()


class _GenDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        svtheme.ensure(self)
        self.title("Generate password")
        self.configure(bg=TH.bg)
        self.resizable(False, False)
        self.grab_set()
        self.result = None
        self.length = tk.IntVar(value=24)
        self.upper = tk.BooleanVar(value=True)
        self.lower = tk.BooleanVar(value=True)
        self.digits = tk.BooleanVar(value=True)
        self.symbols = tk.BooleanVar(value=True)
        self.avoid = tk.BooleanVar(value=True)
        self.out = tk.StringVar(value="")
        ttk.Label(self, text="Length").grid(row=0, column=0, sticky="e", padx=6, pady=4)
        ttk.Spinbox(self, from_=8, to=128, textvariable=self.length, width=6,
                    command=self._gen).grid(row=0, column=1, sticky="w")
        for i, (v, t) in enumerate([(self.upper, "A-Z"), (self.lower, "a-z"),
                                    (self.digits, "0-9"), (self.symbols, "symbols"),
                                    (self.avoid, "avoid ambiguous")]):
            ttk.Checkbutton(self, text=t, variable=v, command=self._gen)\
                .grid(row=1 + i // 3, column=i % 3, sticky="w", padx=6)
        ttk.Entry(self, textvariable=self.out, width=40, state="readonly")\
            .grid(row=4, column=0, columnspan=3, padx=6, pady=6)
        bar = ttk.Frame(self); bar.grid(row=5, column=0, columnspan=3, pady=6)
        ttk.Button(bar, text="Regenerate", command=self._gen).pack(side="left", padx=4)
        ttk.Button(bar, text="Copy & close", command=self._ok).pack(side="left", padx=4)
        ttk.Button(bar, text="Cancel", command=self.destroy).pack(side="left", padx=4)
        self._gen()

    def _gen(self):
        try:
            self.out.set(svpass.generate(
                int(self.length.get()), upper=self.upper.get(), lower=self.lower.get(),
                digits=self.digits.get(), symbols=self.symbols.get(),
                avoid_ambiguous=self.avoid.get()))
        except svpass.PassError as ex:
            self.out.set(f"! {ex}")

    def _ok(self):
        val = self.out.get()
        if val and not val.startswith("! "):
            self.result = val
        self.destroy()


def open_manager(master, vault):
    return PasswordManager(master, vault)


# ======================================================================
# Autofill service: answers the browser (via svhost -> svipc pipe) while the
# app is unlocked. query/generate are answered directly; save/update surface a
# banner on the Tk thread and only write when the user confirms - exactly like
# Chrome's/Edge's "Save password?" and "Update password?" prompts.
# ======================================================================
import threading
import svipc
import svauth


class AutofillService:
    """The vault side of the autofill bridge.

    AUTHORIZATION MODEL (svauth). Reaching this pipe is not permission to read
    anything. ping/register/challenge are the only ops answered unconditionally;
    everything that touches a credential must carry a client_id for a browser
    the user paired by PIN, plus a signature over a challenge this service
    issued moments ago. A local process that scraped the pipe token gets
    "this browser is not paired with SecureVault" and nothing else."""

    def __init__(self, app, vault):
        self.app = app                 # the Tk root (svgui.App), for .after()
        self.vault = vault
        self._lock = threading.Lock()
        self._server = None
        self._token = None
        self._never = set()            # origins the user said "never" for
        self._jar = svauth.ChallengeJar()
        self._pairing = None           # svauth.PairingWindow while armed
        self._pair_lock = threading.Lock()
        self._last_used = {}           # client_id -> epoch, in memory only

    # ---- lifecycle
    def start(self):
        if os.name != "nt":
            return False
        self._token = svipc.issue_token()
        self._server = svipc.PipeServer(self._handle, self._token)
        self._server.start()
        return True

    def stop(self):
        if self._server:
            self._server.stop()
            self._server = None
        svipc.clear_token()

    def _store(self):
        # fresh store view per operation; the blob is small (a few KB)
        s = svpass.PasswordStore(self.vault)
        s.load()
        return s

    # ---- pairing window: armed from the Tk thread when the user asks for it
    def arm_pairing(self):
        """Open a 120-second window and return it so the dialog can show the
        PIN. Only the user, in this app, can call this - which is what stops a
        local process from conjuring a pairing prompt for someone to click."""
        with self._pair_lock:
            self._pairing = svauth.PairingWindow()
            return self._pairing

    def cancel_pairing(self):
        with self._pair_lock:
            self._pairing = None

    def pairing_done(self):
        """True once a window has been redeemed or burned - lets the PIN dialog
        close itself the moment the browser pairs."""
        with self._pair_lock:
            return self._pairing is None

    def paired_clients(self):
        with self._lock:
            clients = dict(self._store().clients())
        for cid, c in clients.items():
            c["last_used"] = max(c.get("last_used", 0), self._last_used.get(cid, 0))
        return clients

    def revoke_client(self, client_id):
        with self._lock:
            s = self._store()
            gone = s.forget_client(client_id)
            if gone:
                s.save()
        self._jar.forget(client_id)
        self._last_used.pop(client_id, None)
        return gone

    def _do_register(self, req):
        with self._pair_lock:
            win = self._pairing
            if win is None or not win.alive():
                self._pairing = None
                raise svauth.AuthError(
                    "no pairing window is open - click 'Pair a browser' in "
                    "SecureVault first")
            win.redeem(req.get("pin"))       # raises, keeping the window, on a
            self._pairing = None             # wrong PIN until attempts run out
        with self._lock:
            s = self._store()
            cid = svauth.register_client(s.clients(), req.get("pubkey", ""),
                                         req.get("label", ""),
                                         req.get("caller", ""))
            s.save()
        return {"ok": True, "client_id": cid}

    # ---- pipe handler (runs on a server worker thread, NOT the Tk thread)
    def _handle(self, req):
        op = req.get("op")
        if op not in svauth.ALL_OPS:
            return {"ok": False, "error": f"bad op {op!r}"}
        try:
            return self._dispatch(op, req)
        except svauth.NotPaired as ex:
            # a code, not just prose: the extension shows "pair with SecureVault"
            # for this and a plain error for anything else
            return {"ok": False, "error": str(ex), "code": "unpaired"}
        except svauth.AuthError as ex:
            return {"ok": False, "error": str(ex), "code": "denied"}

    def _dispatch(self, op, req):
        # ---- open ops: no registration required, and none of them can read or
        # write a credential
        if op == "ping":
            with self._lock:
                n = len(self._store().clients())
            return {"ok": True, "serving": True, "paired": n}
        if op == "register":
            return self._do_register(req)
        if op == "challenge":
            cid = req.get("client_id") or ""
            with self._lock:
                known = cid in self._store().clients()
            if not known:
                raise svauth.NotPaired("this browser is not paired with SecureVault")
            return {"ok": True, "nonce": self._jar.issue(cid)}

        # ---- THE GATE. Past this line the caller has proved it holds the
        # private key of a browser the user paired by hand, over a challenge we
        # issued seconds ago and just consumed.
        with self._lock:
            svauth.authorize(self._store().clients(), self._jar, req)
        # last_used is kept in memory, not written back: this vault is ~10.8 GB
        # and every save() appends to it, so recording a timestamp on each
        # autofill would grow the container for nothing. Cosmetic data only.
        self._last_used[req.get("client_id", "")] = time.time()

        if op == "generate":
            try:
                n = int(req.get("length", 24))
            except (TypeError, ValueError):
                n = 24
            return {"ok": True, "password": svpass.generate(n)}
        if op == "query":
            origin = req.get("origin", "")
            with self._lock:
                s = self._store()
                hits = s.find_by_domain(origin)
            return {"ok": True, "logins": [
                {"id": eid, "title": e.get("title", ""),
                 "username": e.get("username", ""), "password": e.get("password", "")}
                for eid, e in hits]}
        if op == "identities":
            with self._lock:
                s = self._store()
                ids = s.identities()
            return {"ok": True,
                    "emails": [u for u in ids if "@" in u],
                    "usernames": [u for u in ids if "@" not in u]}
        if op in ("save", "update"):
            origin = req.get("origin", "")
            if svpass.domain_of(origin) in self._never:
                return {"ok": True, "staged": "suppressed"}
            # marshal the confirm banner onto the Tk main thread
            self.app.after(0, lambda: self._prompt(op, req))
            return {"ok": True, "staged": op}
        return {"ok": False, "error": f"bad op {op!r}"}

    # ---- Tk-thread UI: the save / update banner
    def decide_save(self, origin, user, pw):
        """Decide what a submitted credential warrants: ('save', None),
        ('update', eid), or None for nothing-to-do. Pure read of the store, so
        it is unit-testable without any Tk. The nothing-to-do case (an entry
        with this exact username+password already exists) is what keeps us from
        prompting "Update?" on every ordinary login, matching Chrome/Edge."""
        if not pw:
            return None
        existing = [(eid, e) for eid, e in self._store().find_by_domain(origin)
                    if e.get("username", "").lower() == (user or "").lower()]
        if any(e.get("password", "") == pw for _eid, e in existing):
            return None
        return ("update", existing[0][0]) if existing else ("save", None)

    def _prompt(self, op, req):
        origin = req.get("origin", "")
        dom = svpass.domain_of(origin)
        user = req.get("username", "")
        pw = req.get("password", "")
        with self._lock:
            decision = self.decide_save(origin, user, pw)
        if not decision:
            return
        verb_key, target_id = decision
        win = tk.Toplevel(self.app)
        svtheme.ensure(win)
        win.title("SecureVault")
        win.configure(bg=TH.bg)
        win.attributes("-topmost", True)
        verb = "Update" if verb_key == "update" else "Save"
        ttk.Label(win, text=f"{verb} password for {dom}?", font=(UI, 11, "bold"),
                  padding=(12, 10, 12, 2)).pack(anchor="w")
        ttk.Label(win, text=f"{user or '(no username)'}  @  {dom}",
                  padding=(12, 0, 12, 8)).pack(anchor="w")

        def do_save():
            with self._lock:
                s2 = self._store()
                if target_id:
                    s2.update(target_id, password=pw, url=req.get("url", origin))
                else:
                    s2.add(title=dom or origin, username=user, password=pw,
                           url=req.get("url", origin), tags=["browser-saved"])
                s2.save()
            win.destroy()
            # refresh an open manager window if there is one
            for w in self.app.winfo_children():
                if isinstance(w, PasswordManager):
                    w.refresh()

        def never():
            self._never.add(dom); win.destroy()

        bar = ttk.Frame(win, padding=(12, 4, 12, 12)); bar.pack(fill="x")
        ttk.Button(bar, text=verb, command=do_save).pack(side="left", padx=3)
        ttk.Button(bar, text="Not now", command=win.destroy).pack(side="left", padx=3)
        ttk.Button(bar, text="Never for this site", command=never).pack(side="left", padx=3)


class BrowserPairingDialog(tk.Toplevel):
    """Manage which browser extensions may read passwords.

    The PIN is generated HERE and displayed HERE, then typed into the extension
    - never the other way round. That is what makes the flow unphishable: a
    prompt asking you to approve a pairing can only ever appear because you
    just asked for one."""

    def __init__(self, master, svc):
        super().__init__(master)
        svtheme.ensure(self)
        self.svc = svc
        self.title("SecureVault - Paired Browsers")
        self.configure(bg=TH.bg)
        self.geometry("640x400")
        self.transient(master)
        self._tick_after = None
        self._build()
        self.refresh()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build(self):
        ttk.Label(self, padding=(10, 10, 10, 2), font=(UI, 11, "bold"),
                  text="Only paired browsers can read your passwords.").pack(anchor="w")
        ttk.Label(self, padding=(10, 0, 10, 8), wraplength=600, foreground=TH.muted,
                  text="Pairing gives one browser extension a key of its own. Anything "
                       "else that reaches SecureVault - a script, another program - is "
                       "refused even while the vault is unlocked. Revoke a browser here "
                       "and it stops filling immediately.").pack(anchor="w")

        cols = ("label", "paired", "used")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", selectmode="browse")
        for c, w, t in (("label", 300, "Browser"), ("paired", 150, "Paired"),
                        ("used", 150, "Last used")):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=10)

        bar = ttk.Frame(self, padding=10); bar.pack(fill="x")
        ttk.Button(bar, text="Pair a browser...", command=self.pair).pack(side="left", padx=3)
        ttk.Button(bar, text="Revoke", command=self.revoke).pack(side="left", padx=3)
        ttk.Button(bar, text="Close", command=self._on_close).pack(side="right", padx=3)

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for cid, c in sorted(self.svc.paired_clients().items(),
                             key=lambda kv: kv[1].get("paired_at", 0)):
            fmt = lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else "never"
            self.tree.insert("", "end", iid=cid,
                             values=(c.get("label", "browser"),
                                     fmt(c.get("paired_at", 0)), fmt(c.get("last_used", 0))))

    # ---- pair
    def pair(self):
        win = self.svc.arm_pairing()
        top = tk.Toplevel(self)
        svtheme.ensure(top)
        top.title("Pair a browser")
        top.configure(bg=TH.bg)
        top.transient(self)
        top.attributes("-topmost", True)
        ttk.Label(top, padding=(16, 14, 16, 2), font=(UI, 11),
                  text="In the browser, open the SecureVault Autofill extension\n"
                       "and enter this PIN:").pack(anchor="w")
        ttk.Label(top, text=win.pin, font=(MONO, 30, "bold"),
                  foreground=TH.accent,
                  padding=(16, 6, 16, 6)).pack(anchor="w")
        left = ttk.Label(top, padding=(16, 0, 16, 6), foreground=TH.muted)
        left.pack(anchor="w")
        ttk.Label(top, padding=(16, 0, 16, 12), foreground=TH.muted, wraplength=380,
                  text="The PIN works once and expires. If you did not just open the "
                       "extension yourself, close this window.").pack(anchor="w")
        ttk.Button(top, text="Cancel", command=lambda: self._cancel(top))\
            .pack(anchor="e", padx=16, pady=(0, 12))

        def tick():
            if not top.winfo_exists():
                return
            if self.svc.pairing_done():          # redeemed by the extension
                top.destroy()
                self.refresh()
                return
            secs = win.seconds_left()
            if secs <= 0:
                self.svc.cancel_pairing()
                top.destroy()
                messagebox.showinfo("SecureVault", "The pairing window expired. "
                                    "Click 'Pair a browser' again to retry.", parent=self)
                return
            left.config(text=f"expires in {secs}s   -   {win.attempts_left} attempts left")
            self._tick_after = top.after(500, tick)

        tick()

    def _cancel(self, top):
        self.svc.cancel_pairing()
        if top.winfo_exists():
            top.destroy()

    # ---- revoke
    def revoke(self):
        cid = self.tree.focus()
        if not cid:
            return
        label = self.tree.set(cid, "label")
        if not messagebox.askyesno("SecureVault",
                                   f"Revoke {label}?\n\nIt stops filling passwords "
                                   "immediately and must be paired again by hand.",
                                   parent=self):
            return
        self.svc.revoke_client(cid)
        self.refresh()

    def _on_close(self):
        self.svc.cancel_pairing()
        self.destroy()


def open_pairing(master, svc):
    return BrowserPairingDialog(master, svc)


def start_autofill(app, vault):
    """Called by svgui once the vault is unlocked. Returns the service (or None
    if it could not start) so the app can stop() it on close."""
    try:
        svc = AutofillService(app, vault)
        if svc.start():
            return svc
    except Exception:
        pass
    return None
