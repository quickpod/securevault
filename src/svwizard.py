#!/usr/bin/env python3
r"""
svwizard - guided tkinter/ttk wizards for SecureVault.

Two flows share one wizard shell (Back / Next / Cancel + a step indicator):

  * launch_autofill_setup(...)   - enable browser autofill without hand-editing
    anything: detect Chromium browsers, run the EXISTING svautofill_setup.apply()
    to generate the extension key/ID and native-host files, register the host and
    (best-effort) allowlist the extension, then walk the user through loading the
    unpacked extension and confirming its ID.

  * launch_password_import(...)  - import saved logins FROM a browser: show
    browser-specific export steps, pick the exported CSV, preview it, then reuse
    svchrome.preview_csv / import_csv / shred_file to merge and securely delete it.

Design rules:
  - Pure tkinter/ttk, resizable, keyboard-friendly (Esc cancels).
  - ALL real work is delegated to existing modules (svautofill_setup, svchrome,
    svpass); this file only orchestrates and renders.
  - Degrades gracefully off Windows: the browser-registry steps report
    "Windows only" instead of crashing, so the UI still imports and renders.
"""

import os, sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HOST_NAME = "com.securevault.autofill"
IS_WINDOWS = sys.platform.startswith("win")


# --------------------------------------------------------------------------- app dir
def default_root():
    r"""The SecureVault install/app directory that holds src\, extension\ and
    nativehost\. In a source tree this is the repo root (parent of src\); in an
    install it is %LOCALAPPDATA%\SecureVault (where src\ was copied)."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- browsers
# Per-browser: install-detection paths + the registry locations Install-BrowserFill.ps1
# uses, plus the pages the user visits by hand. `%VARS%` are expanded at detect time;
# off Windows they stay literal, so nothing is ever found and `found` is False.
_BROWSERS = [
    {"key": "chrome", "name": "Google Chrome",
     "exe": [r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
             r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
             r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"],
     "user_data": r"%LOCALAPPDATA%\Google\Chrome\User Data",
     "native": r"Software\Google\Chrome\NativeMessagingHosts",
     "policy": r"SOFTWARE\Policies\Google\Chrome",
     "ext_url": "chrome://extensions",
     "export_url": "chrome://password-manager/settings",
     "export_steps": [
         "Open  chrome://password-manager/settings",
         "Click  Settings  ->  Export passwords",
         "Confirm with your Windows account when prompted",
         "Save the .csv to a folder only you can read"]},
    {"key": "edge", "name": "Microsoft Edge",
     "exe": [r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
             r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"],
     "user_data": r"%LOCALAPPDATA%\Microsoft\Edge\User Data",
     "native": r"Software\Microsoft\Edge\NativeMessagingHosts",
     "policy": r"SOFTWARE\Policies\Microsoft\Edge",
     "ext_url": "edge://extensions",
     "export_url": "edge://wallet/passwords/settings",
     "export_steps": [
         "Open  edge://wallet/passwords/settings",
         "  (or  Settings -> Profiles -> Passwords)",
         "Click  Export passwords  and confirm with your Windows account",
         "Save the .csv to a folder only you can read"]},
    {"key": "brave", "name": "Brave",
     "exe": [r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe",
             r"%ProgramFiles(x86)%\BraveSoftware\Brave-Browser\Application\brave.exe",
             r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe"],
     "user_data": r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data",
     "native": r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
     "policy": r"SOFTWARE\Policies\BraveSoftware\Brave",
     "ext_url": "brave://extensions",
     "export_url": "brave://settings/passwords",
     "export_steps": [
         "Open  brave://settings/passwords",
         "Click the  ...  next to 'Saved passwords'  ->  Export passwords",
         "Confirm with your Windows account when prompted",
         "Save the .csv to a folder only you can read"]},
]


def detect_browsers():
    """Return one record per known Chromium browser, each annotated with whether
    it appears installed on this machine. Never raises; off Windows every record
    comes back found=False (the paths use Windows env vars that don't expand)."""
    out = []
    for b in _BROWSERS:
        rec = dict(b)
        exe = None
        for cand in b["exe"]:
            p = os.path.expandvars(cand)
            if "%" not in p and os.path.isfile(p):
                exe = p
                break
        ud = os.path.expandvars(b["user_data"])
        ud_ok = "%" not in ud and os.path.isdir(ud)
        rec["exe_path"] = exe
        rec["user_data_path"] = ud if ud_ok else None
        rec["found"] = bool(exe or ud_ok)
        out.append(rec)
    return out


# --------------------------------------------------------------------------- registry
def register_native_host(browser, hostmanifest_path):
    """Point a browser at our native-messaging host manifest (HKCU, no admin).
    Mirrors Install-BrowserFill.ps1's native-host step. Returns True on success.
    Raises on failure so the caller can report per-browser without aborting."""
    if not IS_WINDOWS:
        raise RuntimeError("Windows only")
    import winreg
    keypath = browser["native"] + "\\" + HOST_NAME
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, keypath) as k:
        winreg.SetValueEx(k, "", 0, winreg.REG_SZ, hostmanifest_path)
    return True


def allowlist_extension(browser, ext_id):
    """Add `ext_id` to the browser's ExtensionInstallAllowlist policy (HKLM ->
    needs an elevated process). Mirrors Install-BrowserFill.ps1's Add-Allowlist:
    append a new numbered value without disturbing existing ones. Raises
    PermissionError when not elevated; the caller reports and continues."""
    if not IS_WINDOWS:
        raise RuntimeError("Windows only")
    import winreg
    listpath = browser["policy"] + r"\ExtensionInstallAllowlist"
    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, listpath) as k:
        # already present?
        i, names, values = 0, [], []
        while True:
            try:
                name, val, _ = winreg.EnumValue(k, i)
            except OSError:
                break
            names.append(name)
            values.append(val)
            i += 1
        if ext_id in values:
            return True
        idx = 1
        while str(idx) in names:
            idx += 1
        winreg.SetValueEx(k, str(idx), 0, winreg.REG_SZ, ext_id)
    return True


def open_folder(path):
    """Open a folder in Explorer (Windows) - best effort, never raises."""
    try:
        if IS_WINDOWS and hasattr(os, "startfile"):
            os.startfile(path)  # noqa: cross-platform guarded
            return True
    except Exception:
        pass
    return False


# =========================================================================== shell
class WizardStep:
    """One page. Subclasses override build()/on_show()/on_next()/next_label()."""
    title = ""

    def __init__(self, wiz):
        self.wiz = wiz

    def build(self, parent):
        """Populate `parent` with this step's widgets."""

    def on_show(self):
        """Called every time this step becomes visible (after build)."""

    def on_next(self):
        """Return True to advance, False to stay (after showing your own error)."""
        return True

    def next_label(self):
        return "Next >"


class Wizard(tk.Toplevel):
    r"""Generic Back/Next/Cancel wizard shell. `steps` is a list of WizardStep
    subclasses (not instances); `state` is a shared dict every step can read/write.
    When `master` is None it creates and owns a hidden root so the wizard can run
    standalone (used by the module smoke test)."""

    def __init__(self, master, title, step_classes, state=None):
        self._owns_root = master is None
        if self._owns_root:
            self._root = tk.Tk()
            self._root.withdraw()
            super().__init__(self._root)
        else:
            self._root = None
            super().__init__(master)

        self.title(title)
        self.state = state if state is not None else {}
        self.geometry("640x520")
        self.minsize(520, 420)
        self._set_icon()

        self.steps = [cls(self) for cls in step_classes]
        self.idx = 0

        outer = ttk.Frame(self, padding=0)
        outer.pack(fill="both", expand=True)

        head = ttk.Frame(outer, padding=(16, 12, 16, 8))
        head.pack(fill="x")
        self.head_title = ttk.Label(head, text="", font=("Segoe UI", 13, "bold"))
        self.head_title.pack(anchor="w")
        self.head_step = ttk.Label(head, text="", foreground="#666")
        self.head_step.pack(anchor="w")
        ttk.Separator(outer, orient="horizontal").pack(fill="x")

        self.body = ttk.Frame(outer, padding=(16, 12))
        self.body.pack(fill="both", expand=True)

        ttk.Separator(outer, orient="horizontal").pack(fill="x")
        foot = ttk.Frame(outer, padding=(16, 10))
        foot.pack(fill="x")
        self.btn_cancel = ttk.Button(foot, text="Cancel", command=self._cancel)
        self.btn_cancel.pack(side="right")
        self.btn_next = ttk.Button(foot, text="Next >", command=self._next)
        self.btn_next.pack(side="right", padx=(0, 8))
        self.btn_back = ttk.Button(foot, text="< Back", command=self._back)
        self.btn_back.pack(side="right", padx=(0, 8))

        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.bind("<Escape>", lambda _e: self._cancel())
        self._show()
        try:
            self.transient(master) if master else None
            self.lift()
            self.focus_set()
        except Exception:
            pass

    # ---- helpers steps can use
    def _set_icon(self):
        try:
            here = os.path.dirname(os.path.abspath(__file__))
            for r in (here, os.path.dirname(here)):
                ico = os.path.join(r, "securevault.ico")
                if os.path.exists(ico):
                    self.iconbitmap(ico)
                    return
        except Exception:
            pass

    def para(self, parent, text, **kw):
        """A wrapping paragraph label that reflows with the window width."""
        lbl = ttk.Label(parent, text=text, justify="left", anchor="w", **kw)
        lbl.pack(fill="x", pady=(0, 8))

        def _wrap(_e=None):
            w = parent.winfo_width() - 8
            if w > 40:
                lbl.configure(wraplength=w)
        parent.bind("<Configure>", _wrap, add="+")
        lbl.after(30, _wrap)
        return lbl

    def readonly_text(self, parent, content, height=8):
        """A selectable read-only text block (for steps/paths/logs)."""
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, pady=(0, 8))
        txt = tk.Text(frame, height=height, wrap="word", relief="solid", bd=1)
        vs = ttk.Scrollbar(frame, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)
        txt.insert("1.0", content)
        txt.configure(state="disabled")
        return txt

    def copy_to_clipboard(self, text):
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            return True
        except Exception:
            return False

    # ---- navigation
    def _clear_body(self):
        for w in self.body.winfo_children():
            w.destroy()

    def _show(self):
        step = self.steps[self.idx]
        self.head_title.configure(text=step.title)
        self.head_step.configure(
            text=f"Step {self.idx + 1} of {len(self.steps)}")
        self._clear_body()
        step.build(self.body)
        step.on_show()
        self.btn_back.configure(state=("disabled" if self.idx == 0 else "normal"))
        last = self.idx == len(self.steps) - 1
        self.btn_next.configure(text=("Finish" if last else step.next_label()))
        self.btn_cancel.configure(text=("Close" if last else "Cancel"))
        self.btn_next.focus_set()

    def _next(self):
        step = self.steps[self.idx]
        try:
            ok = step.on_next()
        except Exception as ex:
            messagebox.showerror("SecureVault", str(ex), parent=self)
            return
        if not ok:
            return
        if self.idx == len(self.steps) - 1:
            self._finish()
            return
        self.idx += 1
        self._show()

    def _back(self):
        if self.idx > 0:
            self.idx -= 1
            self._show()

    def _cancel(self):
        self._close()

    def _finish(self):
        self._close()

    def _close(self):
        try:
            self.destroy()
        finally:
            if self._owns_root and self._root is not None:
                try:
                    self._root.destroy()
                except Exception:
                    pass

    def run_modal(self):
        """Block until the wizard closes (used for standalone launches)."""
        if self._owns_root and self._root is not None:
            self._root.wait_window(self)
        else:
            self.wait_window(self)


# =========================================================================== autofill flow
class _AFIntro(WizardStep):
    title = "Browser autofill - how it works"

    def build(self, parent):
        self.wiz.para(parent,
            "This wizard sets up SecureVault's browser autofill so you can fill "
            "and save logins straight from Chrome, Edge or Brave.")
        self.wiz.readonly_text(parent, height=9, content=(
            "LOCAL-ONLY, BY DESIGN\n"
            "• The browser extension talks ONLY to the SecureVault app on this "
            "machine, through a native-messaging host (a small relay). It never "
            "talks to the cloud and sends nothing over the network.\n\n"
            "• The relay holds NO keys and can decrypt nothing. Autofill works "
            "only while SecureVault is OPEN and UNLOCKED - close or lock the vault "
            "and every request simply fails.\n\n"
            "• Each browser must additionally be PAIRED from the app "
            "(Passwords -> Browsers...) before it can touch a stored credential."))
        if not IS_WINDOWS:
            self.wiz.para(parent,
                "NOTE: this machine is not Windows. The wizard will render and "
                "explain each step, but the browser/registry actions are Windows-"
                "only and will be reported as skipped.",
                foreground="#b0700a")


class _AFDetect(WizardStep):
    title = "Choose your browsers"

    def build(self, parent):
        self.wiz.para(parent,
            "Select the browsers to set up. Detected browsers are ticked by "
            "default; you can enable one that wasn't detected if you use a "
            "portable/custom install.")
        self.vars = {}
        browsers = self.wiz.state.setdefault("browsers", detect_browsers())
        any_found = any(b["found"] for b in browsers)
        box = ttk.Frame(parent)
        box.pack(fill="x", pady=4)
        for b in browsers:
            v = tk.BooleanVar(value=(b["found"] or not any_found))
            self.vars[b["key"]] = v
            label = f"{b['name']}   " + ("(detected)" if b["found"] else "(not detected)")
            ttk.Checkbutton(box, text=label, variable=v).pack(anchor="w", pady=2)
        if not any_found:
            self.wiz.para(parent,
                "No Chromium browsers were detected on this machine. You can still "
                "proceed and load the extension into any Chromium browser by hand.",
                foreground="#b0700a")

    def on_next(self):
        chosen = [k for k, v in self.vars.items() if v.get()]
        self.wiz.state["selected"] = chosen
        if not chosen and not messagebox.askyesno(
                "SecureVault",
                "No browser is selected. Continue anyway (you can load the "
                "extension by hand later)?", parent=self.wiz):
            return False
        return True


class _AFInstall(WizardStep):
    title = "Install the bridge"

    def next_label(self):
        return "Next >"

    def build(self, parent):
        self.wiz.para(parent,
            "Generating the extension key/ID and native-host files, then "
            "registering the host for the selected browsers...")
        self.log = self.wiz.readonly_text(parent, "", height=12)
        self._done = False

    def _append(self, line):
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")
        self.log.update_idletasks()

    def on_show(self):
        if self._done:
            return
        self._done = True
        root = self.wiz.state["root_dir"]
        # 1. reuse svautofill_setup.apply() - generates the key/ID + writes every
        #    native-host/extension file. Single source of truth for that logic.
        try:
            import svautofill_setup
            info = svautofill_setup.apply(root)
            self.wiz.state["apply"] = info
            self._append(f"Generated extension key + ID: {info['ext_id']}")
            self._append(f"Native-host manifest: {info['hostmanifest']}")
            self._append(f"Extension folder:     {os.path.join(root, 'extension')}")
        except Exception as ex:
            self.wiz.state["apply"] = None
            self._append(f"ERROR generating bridge files: {ex}")
            self._append("Cannot continue without these files. Check that the "
                         "'cryptography' package is installed.")
            return

        info = self.wiz.state["apply"]
        if not IS_WINDOWS:
            self._append("")
            self._append("Windows only: skipping browser/registry registration "
                         "on this platform.")
            return

        # 2. per-browser: register the native host (HKCU) + allowlist (HKLM).
        by_key = {b["key"]: b for b in self.wiz.state["browsers"]}
        results = {}
        for key in self.wiz.state.get("selected", []):
            b = by_key.get(key)
            if not b:
                continue
            self._append("")
            self._append(f"-- {b['name']} --")
            try:
                register_native_host(b, info["hostmanifest"])
                self._append("  native host registered (HKCU)")
                reg_ok = True
            except Exception as ex:
                self._append(f"  native host FAILED: {ex}")
                reg_ok = False
            try:
                allowlist_extension(b, info["ext_id"])
                self._append("  extension allowlisted (HKLM policy)")
                allow_ok = True
            except PermissionError:
                self._append("  allowlist needs an ELEVATED prompt - skipped. "
                             "Re-run SecureVault as admin, or the extension may be "
                             "blocked by an existing Chrome/Edge policy blocklist.")
                allow_ok = False
            except Exception as ex:
                self._append(f"  allowlist skipped: {ex}")
                allow_ok = False
            results[key] = {"registered": reg_ok, "allowlisted": allow_ok}
        self.wiz.state["install_results"] = results
        self._append("")
        self._append("Done. Click Next to load the extension.")


class _AFLoad(WizardStep):
    title = "Load the extension"

    def build(self, parent):
        root = self.wiz.state["root_dir"]
        extdir = os.path.join(root, "extension")
        self.wiz.state["extdir"] = extdir
        self.wiz.para(parent,
            "Browsers cannot be scripted into loading an unpacked extension, so "
            "this one step is by hand (once):")
        self.wiz.readonly_text(parent, height=7, content=(
            "1. Open your browser's extensions page:\n"
            "     Chrome  ->  chrome://extensions\n"
            "     Edge    ->  edge://extensions\n"
            "     Brave   ->  brave://extensions\n"
            "   (These pages can't be opened from an app - type/paste the address.)\n"
            "2. Turn ON 'Developer mode' (top-right toggle).\n"
            "3. Click 'Load unpacked' and choose the folder below.\n"
            "4. The SecureVault Autofill extension appears in the list."))
        self.wiz.para(parent, "Extension folder to select:")
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=(0, 6))
        ent = ttk.Entry(row)
        ent.insert(0, extdir)
        ent.configure(state="readonly")
        ent.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Copy",
                   command=lambda: self.wiz.copy_to_clipboard(extdir)).pack(side="left", padx=(6, 0))
        btns = ttk.Frame(parent)
        btns.pack(fill="x")
        ttk.Button(btns, text="Open extension folder",
                   command=self._open).pack(side="left")

    def _open(self):
        if not open_folder(self.wiz.state["extdir"]):
            messagebox.showinfo(
                "SecureVault",
                "Open this folder in your file manager, then pick it in "
                f"'Load unpacked':\n\n{self.wiz.state['extdir']}", parent=self.wiz)


class _AFConfirmId(WizardStep):
    title = "Confirm the extension ID"

    def build(self, parent):
        info = self.wiz.state.get("apply") or {}
        derived = info.get("ext_id", "")
        self.wiz.para(parent,
            "Because SecureVault pins a fixed signing key into the extension "
            "manifest, the browser should assign this exact ID:")
        self.wiz.readonly_text(parent, height=2, content=(derived or "(unavailable)"))
        self.wiz.para(parent,
            "Open your extensions page and check the ID under 'SecureVault "
            "Autofill'. If it matches, you're done here. If the browser shows a "
            "DIFFERENT ID, paste it below and click 'Use this ID' - the native "
            "host's allowed_origins will be rewritten to match.")
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=(0, 6))
        ttk.Label(row, text="Extension ID:").pack(side="left")
        self.id_var = tk.StringVar(value=derived)
        self.entry = ttk.Entry(row, textvariable=self.id_var)
        self.entry.pack(side="left", fill="x", expand=True, padx=(6, 6))
        ttk.Button(row, text="Use this ID", command=self._apply_id).pack(side="left")
        self.msg = ttk.Label(parent, text="", foreground="#0a7a0a", justify="left")
        self.msg.pack(anchor="w")

    @staticmethod
    def _valid(ext_id):
        return len(ext_id) == 32 and all("a" <= c <= "p" for c in ext_id)

    def _apply_id(self):
        ext_id = self.id_var.get().strip().lower()
        if not self._valid(ext_id):
            messagebox.showerror(
                "SecureVault",
                "That doesn't look like a Chrome extension ID (expect 32 letters "
                "a-p).", parent=self.wiz)
            return
        origin = f"chrome-extension://{ext_id}/"
        try:
            import svautofill_setup
            svautofill_setup.set_allowed_origin(self.wiz.state["root_dir"], origin)
        except Exception as ex:
            messagebox.showerror("SecureVault", f"Could not update files:\n{ex}",
                                 parent=self.wiz)
            return
        # re-point the browsers we registered so the host manifest change is live
        if IS_WINDOWS:
            by_key = {b["key"]: b for b in self.wiz.state["browsers"]}
            for key in self.wiz.state.get("selected", []):
                b = by_key.get(key)
                if not b:
                    continue
                try:
                    allowlist_extension(b, ext_id)
                except Exception:
                    pass
        self.wiz.state["final_ext_id"] = ext_id
        self.msg.configure(
            text=f"Updated. Native host now trusts:\n{origin}")


class _AFDone(WizardStep):
    title = "All set"

    def build(self, parent):
        info = self.wiz.state.get("apply") or {}
        ext_id = self.wiz.state.get("final_ext_id") or info.get("ext_id", "(n/a)")
        by_key = {b["key"]: b for b in self.wiz.state["browsers"]}
        lines = ["Configured:", ""]
        results = self.wiz.state.get("install_results", {})
        sel = self.wiz.state.get("selected", [])
        if sel:
            for key in sel:
                b = by_key.get(key)
                r = results.get(key, {})
                if not b:
                    continue
                bits = []
                bits.append("host registered" if r.get("registered") else "host NOT registered")
                bits.append("allowlisted" if r.get("allowlisted") else "not allowlisted")
                lines.append(f"  • {b['name']}: " + ", ".join(bits))
        else:
            lines.append("  • (no browser registered - load the extension by hand)")
        lines += [
            "",
            f"Extension ID: {ext_id}",
            "",
            "TO TEST:",
            "  1. Keep SecureVault open and unlocked.",
            "  2. In the app: Passwords -> Browsers... -> Pair a browser, and enter",
            "     the shown PIN in the browser's SecureVault popup.",
            "  3. Visit a login page - matching logins are offered inline.",
            "",
            "TO REMOVE LATER:",
            "  • Run  uninstall.ps1,  or  Install-BrowserFill.ps1 -Revert",
            "  • Remove the unpacked extension from the browser's extensions page."]
        self.wiz.readonly_text(parent, "\n".join(lines), height=15)
        # optional bridge into the password-import wizard
        app = self.wiz.state.get("app")
        if app is not None:
            ttk.Button(parent, text="Import passwords from browser now...",
                       command=lambda: self._import(app)).pack(anchor="w", pady=(4, 0))

    def _import(self, app):
        self.wiz._close()
        try:
            launch_password_import(master=app, app=app, vault=getattr(app, "vault", None))
        except Exception as ex:
            messagebox.showerror("SecureVault", str(ex))


_AUTOFILL_STEPS = [_AFIntro, _AFDetect, _AFInstall, _AFLoad, _AFConfirmId, _AFDone]


def launch_autofill_setup(master=None, root_dir=None, app=None):
    """Open the browser-autofill setup wizard. `master` is a Tk widget to parent
    to (None => run standalone). `app` (the running GUI App) enables the optional
    'import passwords now' hand-off on the final page."""
    state = {"root_dir": root_dir or default_root(), "app": app}
    wiz = Wizard(master, "SecureVault - Set up browser autofill",
                 _AUTOFILL_STEPS, state)
    if master is None:
        wiz.run_modal()
    return wiz


# =========================================================================== import flow
class _IMExport(WizardStep):
    title = "Export your browser passwords"

    def build(self, parent):
        self.wiz.para(parent,
            "First, export your saved logins from the browser to a CSV file. "
            "Pick your browser for the exact steps:")
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=(0, 6))
        ttk.Label(row, text="Browser:").pack(side="left")
        keys = [b["key"] for b in _BROWSERS]
        names = {b["key"]: b["name"] for b in _BROWSERS}
        default = self.wiz.state.get("import_browser") or keys[0]
        self.sel = tk.StringVar(value=default)
        self.combo = ttk.Combobox(row, state="readonly",
                                  values=[names[k] for k in keys], width=22)
        self.combo.current(keys.index(default))
        self.combo.pack(side="left", padx=(6, 0))
        self.combo.bind("<<ComboboxSelected>>", lambda _e: self._render())
        self._keys = keys
        self.steps_txt = self.wiz.readonly_text(parent, "", height=7)
        self._render()
        warn = tk.Text(parent, height=5, wrap="word", relief="solid", bd=1)
        warn.pack(fill="x", pady=(4, 0))
        warn.insert("1.0",
            "SECURITY WARNING\n"
            "The exported CSV is PLAINTEXT - anyone who reads the file reads every "
            "password. Save it to a folder only your Windows account can read, and "
            "NEVER onto a removable or network drive, or a synced folder "
            "(OneDrive/Dropbox). This wizard securely shreds the CSV right after "
            "importing it.")
        warn.configure(state="disabled", foreground="#a11")

    def _render(self):
        key = self._keys[self.combo.current()]
        b = next(x for x in _BROWSERS if x["key"] == key)
        body = "\n".join(f"{i+1}. {s}" for i, s in enumerate(b["export_steps"]))
        self.steps_txt.configure(state="normal")
        self.steps_txt.delete("1.0", "end")
        self.steps_txt.insert("1.0", body)
        self.steps_txt.configure(state="disabled")

    def on_next(self):
        self.wiz.state["import_browser"] = self._keys[self.combo.current()]
        return True


class _IMPick(WizardStep):
    title = "Pick the exported CSV"

    def build(self, parent):
        self.wiz.para(parent,
            "Choose the CSV you just exported. SecureVault reads it, shows a "
            "summary (never the passwords themselves), then imports on the next "
            "step.")
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=(0, 6))
        self.path_var = tk.StringVar(value=self.wiz.state.get("csv_path", ""))
        ent = ttk.Entry(row, textvariable=self.path_var)
        ent.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse...", command=self._pick).pack(side="left", padx=(6, 0))
        self.summary = self.wiz.readonly_text(parent, "", height=11)
        if self.path_var.get():
            self._preview(self.path_var.get())

    def _pick(self):
        path = filedialog.askopenfilename(
            parent=self.wiz, title="Select the exported passwords CSV",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        self.path_var.set(path)
        self._preview(path)

    def _preview(self, path):
        self.summary.configure(state="normal")
        self.summary.delete("1.0", "end")
        try:
            import svchrome
            prev = svchrome.preview_csv(path)
        except Exception as ex:
            self.summary.insert("1.0", f"Could not read this file:\n{ex}")
            self.summary.configure(state="disabled")
            self.wiz.state["preview"] = None
            return
        self.wiz.state["preview"] = prev
        lines = [f"Found {prev['total']} credential(s)  "
                 f"({prev['with_password']} with a password).",
                 f"Skippable/blank rows: {prev['skipped_blank']}.",
                 "", "Sample (no passwords shown):"]
        for s in prev["sample"]:
            dom = s.get("domain") or ""
            lines.append(f"  • {s['title']}   {s['username']}   {dom}")
        if not prev["sample"]:
            lines.append("  (none)")
        self.summary.insert("1.0", "\n".join(lines))
        self.summary.configure(state="disabled")

    def on_next(self):
        path = self.path_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("SecureVault", "Pick an existing CSV file first.",
                                 parent=self.wiz)
            return False
        if self.wiz.state.get("preview") is None:
            messagebox.showerror(
                "SecureVault",
                "That file couldn't be read as a password export. Pick another.",
                parent=self.wiz)
            return False
        self.wiz.state["csv_path"] = path
        return True


class _IMImport(WizardStep):
    title = "Import into the vault"

    def next_label(self):
        return "Import >"

    def build(self, parent):
        prev = self.wiz.state.get("preview") or {}
        self.wiz.para(parent,
            f"Ready to import {prev.get('total', 0)} credential(s) into your open "
            "vault's password manager.")
        self.skip_dup = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent,
            text="Skip duplicates (same username on the same domain)",
            variable=self.skip_dup).pack(anchor="w", pady=(0, 8))
        self.result = self.wiz.readonly_text(parent, "", height=8)
        self._imported = False

    def on_next(self):
        if self._imported:
            return True
        store = self._get_store()
        if store is None:
            messagebox.showerror(
                "SecureVault",
                "No unlocked vault is available. Open a vault first, then run "
                "this import from its window.", parent=self.wiz)
            return False
        path = self.wiz.state["csv_path"]
        try:
            import svchrome
            res = svchrome.import_csv(store, path,
                                      skip_duplicates=self.skip_dup.get())
            store.save()
        except Exception as ex:
            messagebox.showerror("SecureVault", f"Import failed:\n{ex}",
                                 parent=self.wiz)
            return False
        self.wiz.state["import_result"] = res
        self.result.configure(state="normal")
        self.result.delete("1.0", "end")
        self.result.insert("1.0",
            f"Imported {res.get('added', 0)} new login(s).\n"
            f"Skipped {res.get('duplicates', 0)} duplicate(s).\n"
            f"Parsed {res.get('parsed', 0)} row(s) total.\n\n"
            "Click Next to securely delete the plaintext CSV.")
        self.result.configure(state="disabled")
        self._imported = True
        # keep the user on this page so they see the result before continuing
        self.wiz.btn_next.configure(text="Next >")
        return False

    def _get_store(self):
        # Prefer a store the caller handed us; else build one from the open vault
        # exactly as the password manager does (svpassgui: PasswordStore(vault)).
        store = self.wiz.state.get("store")
        if store is not None:
            return store
        vault = self.wiz.state.get("vault")
        if vault is None:
            app = self.wiz.state.get("app")
            vault = getattr(app, "vault", None) if app else None
        if vault is None:
            return None
        try:
            import svpass
            store = svpass.PasswordStore(vault)
            store.load()
            self.wiz.state["store"] = store
            return store
        except Exception:
            return None


class _IMShred(WizardStep):
    title = "Shred the plaintext CSV"

    def build(self, parent):
        path = self.wiz.state.get("csv_path", "")
        self.wiz.para(parent,
            "The exported CSV is plaintext and should not linger on disk. "
            "SecureVault can overwrite and delete it now (best-effort secure "
            "delete).")
        self.shred = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, text="Securely delete the CSV now",
                        variable=self.shred).pack(anchor="w", pady=(0, 6))
        self.wiz.readonly_text(parent, height=2, content=(path or "(no file)"))
        self.msg = ttk.Label(parent, text="", justify="left")
        self.msg.pack(anchor="w")
        self._done = False

    def on_next(self):
        if self._done or not self.shred.get():
            self.wiz.state["shredded"] = self.wiz.state.get("shredded", False)
            return True
        path = self.wiz.state.get("csv_path", "")
        try:
            import svchrome
            ok = svchrome.shred_file(path)
        except Exception:
            ok = False
        self.wiz.state["shredded"] = ok
        self._done = True
        self.msg.configure(
            foreground=("#0a7a0a" if ok else "#a11"),
            text=("Shredded and deleted the CSV." if ok else
                  "Could not delete the CSV - remove it by hand."))
        messagebox.showinfo(
            "SecureVault",
            ("The CSV was securely deleted." if ok else
             "Could not delete the CSV automatically - delete it by hand.") +
            "\n\nIf you exported into a synced folder (OneDrive/Dropbox), also "
            "purge it there AND empty the online trash.", parent=self.wiz)
        return True


class _IMDone(WizardStep):
    title = "Import complete"

    def build(self, parent):
        res = self.wiz.state.get("import_result") or {}
        shredded = self.wiz.state.get("shredded", False)
        lines = [
            f"Imported {res.get('added', 0)} login(s); "
            f"skipped {res.get('duplicates', 0)} duplicate(s).",
            "",
            "Imported items are tagged  'chrome-import'  so you can find and "
            "review them: open Passwords and filter/scan for that tag.",
            "",
            ("The plaintext CSV was securely deleted." if shredded else
             "Remember to delete the plaintext CSV you exported."),
            "",
            "Tip: run the password manager's Audit... to spot reused or weak "
            "passwords among the imported logins."]
        self.wiz.readonly_text(parent, "\n".join(lines), height=12)


_IMPORT_STEPS = [_IMExport, _IMPick, _IMImport, _IMShred, _IMDone]


def launch_password_import(master=None, app=None, vault=None, store=None,
                           import_browser=None):
    """Open the browser-password import wizard. Needs an UNLOCKED vault: pass the
    running `app` (its .vault is used) and/or an explicit `vault`/`store`. If none
    is available the import step tells the user to open a vault first."""
    if vault is None and app is not None:
        vault = getattr(app, "vault", None)
    if store is None and app is not None and vault is None:
        messagebox.showinfo(
            "SecureVault",
            "Open a vault first, then run 'Import passwords from browser...' from "
            "its window.", parent=master)
        return None
    state = {"app": app, "vault": vault, "store": store,
             "import_browser": import_browser}
    wiz = Wizard(master, "SecureVault - Import passwords from browser",
                 _IMPORT_STEPS, state)
    if master is None:
        wiz.run_modal()
    return wiz


# --------------------------------------------------------------------------- smoke test
if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "autofill"
    print("detect_browsers ->")
    for b in detect_browsers():
        print(f"  {b['name']:16} found={b['found']} exe={b['exe_path']}")
    if os.environ.get("SVWIZARD_NODISPLAY"):
        print("SVWIZARD_NODISPLAY set: skipping window.")
        sys.exit(0)
    if which == "import":
        launch_password_import()
    else:
        launch_autofill_setup()
