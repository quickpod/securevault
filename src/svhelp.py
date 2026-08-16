#!/usr/bin/env python3
r"""
svhelp - SecureVault's in-app help viewer.

A plain tk Toplevel: topic list on the left, rendered text on the right, an
action row underneath for the buttons a topic needs (e.g. "Open extension
folder"). Everything draws from the Aura palette via svtheme, so it follows
Dark/Light like the rest of the app, and the content is authored here as
plain text with two markups only: lines starting with "## " render as section
headings, lines starting with "  $" render monospaced (paths/commands).

The SAME content ships as docs/USAGE.md prose; when editing one, check the
other (the paths below are user-facing documentation - the packaging installs
the extension folder at exactly these locations on purpose).
"""
import os, sys
import tkinter as tk
from tkinter import ttk, messagebox

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import svtheme
from svtheme import TH, UI, MONO

IS_WINDOWS = os.name == "nt"


# ------------------------------------------------------------------ paths
def extension_dir():
    """The unpacked-extension folder a user selects in 'Load unpacked'.
    Windows: %LOCALAPPDATA%\SecureVault\extension (written by the autofill
    wizard / installer). Linux: the packaged app dir - stable, documented."""
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
        p = os.path.join(base, "SecureVault", "extension")
        if os.path.isdir(p):
            return p
    import svautofill_setup
    return os.path.join(svautofill_setup.app_root(), "extension")


def open_folder(path):
    try:
        if IS_WINDOWS and hasattr(os, "startfile"):
            os.startfile(path)  # noqa: guarded
            return True
        import subprocess
        subprocess.Popen(["xdg-open", path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


# ------------------------------------------------------------------ content
def _topics():
    ext = extension_dir()
    win_ext = r"%LOCALAPPDATA%\SecureVault\extension"
    lin_ext = "/opt/quickopen/securevault/extension"
    plat_ext = win_ext if IS_WINDOWS else lin_ext

    t = []

    t.append(("Getting started", f"""\
## What SecureVault is

One encrypted container file (SecureVault.dat) that holds your files and your
passwords. Without your factors it is cryptographic noise - there is no cloud,
no account, no recovery service. Only you can open it.

## The three factors

Opening a vault always takes:
  1. your master PASSWORD (typed),
  2. your 6-digit PIN (clicked on the randomized on-screen pad - never typed,
     so a keylogger cannot capture it),
  3. a rotating code from your AUTHENTICATOR app (enrolled when the vault was
     created - Google Authenticator, Aegis, Authy, 1Password all work).

There is no "forgot password". Losing the factors means losing the vault:
that is the design, not an accident.

## Create / open / lock

* First launch offers "Create new vault". Pick where the file lives - the
  default is {'next to the program' if IS_WINDOWS else '~/.local/share/securevault/SecureVault.dat'};
  a USB stick or a synced folder works too (the file is safe to copy around).
* CLOSING THE WINDOW LOCKS THE VAULT - unless you choose "Run in background"
  in the close prompt, which keeps autofill available from a tray icon (see
  the "Background mode & tray" topic). Locking wipes decrypted scratch
  copies, stops browser autofill, and seals the vault until the three
  factors open it again.
* File > Open Vault / Open Recent switches between containers.

## Everyday use

* Add Files / Add Folder encrypts things in (optionally deleting originals).
* Double-click a file to open it in its normal application; SecureVault wipes
  the decrypted copy when the app closes and offers to save edits back.
* Extract decrypts things out. Delete removes and compacts.
* Preview shows small text/images without writing anything to disk.
""", []))

    t.append(("Passwords & generator", """\
## The password manager

Click "Passwords" in the toolbar (or Tools > Passwords). Entries hold a title,
username, password, URL, tags, notes and an optional TOTP secret - so the
vault can show login codes for your other accounts too.

## Generating passwords

In the password manager, "Generate..." makes a random password (length and
character classes are up to you; "avoid ambiguous" drops 0/O/1/l). The
browser extension can also ask the vault for a generated password while
you're on a signup page.

## Import from a browser

Tools > Import passwords from browser... walks through exporting a CSV from
Chrome/Edge/Brave, imports it (skipping duplicates), then SHREDS the
plaintext CSV. Imported entries are tagged 'chrome-import'.

## Audit

The manager's Audit finds reused and weak passwords. Worth running after an
import.
""", []))

    t.append(("Backup & restore", """\
## Backing up

The whole vault is the single .dat file. Backing up = copying that file
anywhere: another disk, a USB stick, a cloud-synced folder. The copy is as
encrypted as the original, so an attacker who steals the backup still needs
all three factors.

Do it on a schedule, and after big additions. The title bar shows the full
path of the open vault.

## Restoring

Copy the .dat back (or to a new machine), start SecureVault, File > Open
Vault, pick the file, enter your factors. Vault files move cleanly between
Windows and Linux - the format is identical on both.

## Integrity

Tools > Verify integrity re-authenticates every stored file against its
encryption tag and checksum. Run it after moving the file between machines
or if a disk was flaky.

## What to keep safe besides the file

Your authenticator enrollment (or the TOTP secret you saved at creation) and
your password + PIN. A backup of the .dat without the factors is noise.
""", []))

    t.append(("Browser autofill & pairing", f"""\
## What it is

A browser extension that fills, saves and generates passwords straight from
this vault. Local-only by design: the extension talks to a small relay on
this machine, the relay talks to the RUNNING, UNLOCKED SecureVault app, and
nothing ever touches the network.

## Pairing, step by step

Pairing is a one-time trust ceremony per browser profile, and it always
starts IN THE APP - never in the browser:

  1. Keep SecureVault open and unlocked.
  2. Open Passwords -> Browsers... and click "Pair a browser".
  3. The app shows a 6-digit PIN (valid ~2 minutes, 3 attempts).
  4. In the browser, click the SecureVault Autofill icon and type that PIN.
  5. The row appears in the Browsers list. Done - visit a login page and
     matching logins are offered.

If nothing happens in step 4: the extension is not installed or the vault is
closed - see "Install the extension" and "Troubleshooting". The popup keeps
checking while open, so unlocking the vault flips it to "connected" by
itself. The PIN box takes digits only and pairs as soon as the 6th digit is
typed.

## Using it day to day

* Focus a login field and matching logins drop down. Arrow keys move,
  Enter fills, Escape closes. Passwords stay masked bullets.
* A small vault badge sits inside password fields - click it to reopen the
  menu after dismissing it.
* The extension icon's popup shows the current site's saved-login count and
  quick actions: "Fill on this page", "Generate password" (copies it),
  "Open vault". If SecureVault isn't running, the popup offers to start it;
  if it's locked, it says to unlock it in the app.
* Sites with exactly ONE saved login fill automatically on load.

## Unpairing / revoking

Passwords -> Browsers... -> Revoke. The browser loses access immediately and
must be paired again by hand. Revoke anything you don't recognise.

## When autofill works

Only while the SecureVault window is open and unlocked. Close the app and
every fill stops mid-sentence - that is the point.
""", []))

    quick_note = ("## Quick Browser (Quick OS)\n\n"
                  "Nothing to install: Quick Browser ships with the SecureVault\n"
                  "extension pre-installed. Open the vault, pair (previous topic),\n"
                  "and it fills.\n\n") if not IS_WINDOWS else ""
    t.append(("Install the extension", f"""\
{quick_note}## Chrome / Edge / other Chromium browsers (manual, once)

Browsers cannot be scripted into loading an unpacked extension, so this one
step is by hand:

  1. Open the extensions page (type it in the address bar):
       Chrome ->  chrome://extensions
       Edge   ->  edge://extensions
  2. Turn ON "Developer mode" (top-right toggle).
  3. Click "Load unpacked" and select this folder:
  $  {plat_ext}
  4. "SecureVault Autofill" appears in the list. Now pair it (previous topic).

The extension folder on this machine:
  $  {ext}

## Why no web store?

Publishing to a store would mean an account, updates from the network and a
middleman - everything this app avoids. The unpacked extension is versioned
and shipped with SecureVault itself.

## The native host

The extension reaches the vault through a registered "native messaging host".
{'The installer/wizard registers it for Chrome and Edge automatically.' if IS_WINDOWS else
 'The SecureVault package installs it system-wide for Quick Browser, Chrome and Edge; Tools > Set up browser autofill... adds per-user copies for other Chromium browsers.'}
If a browser was installed AFTER SecureVault, run Tools > Set up browser
autofill... once.
""", [("Open extension folder", lambda: open_folder(ext))]))

    t.append(("Background mode & tray", """\
## Why run in the background?

Browser autofill only works while SecureVault is running and unlocked. If
you close the window, autofill stops mid-browsing. "Run in background" keeps
the vault process alive with a tray icon instead, so the extension keeps
filling while no window is on screen.

## The close prompt

Closing the window with an open vault asks once: "Run in background" or
"Close & lock", with a "remember my choice" box. Change the remembered
choice any time in Tools > Preferences.

## The tray icon

* A green dot means unlocked (autofill available); grey means locked.
* Click (or "Open SecureVault") brings the window back.
* "Lock now" locks immediately: the autofill endpoint disappears, the
  transport token is destroyed, decrypted scratch copies are wiped. The icon
  stays, showing locked; opening again asks for all three factors.
* "Quit (lock and exit)" does the same and then exits completely.

## Auto-lock

A background vault must not stay unlocked forever. After a period of
inactivity in the tray (default 15 minutes; autofill requests count as
activity) it locks itself. Set the timeout in Tools > Preferences - there is
deliberately no "never".

## Nothing secret in the tray

The tooltip and menu show only "unlocked/locked" and a paired-browser count -
never a vault path, an entry name or any credential.
""", []))

    t.append(("Security model, plainly", """\
## Encryption

Your password + PIN are stretched (scrypt) into a key that unwraps the
vault's data key; every file and the index are AES-256-GCM encrypted and
authenticated. The same parameters on Windows and Linux - a vault file is
byte-for-byte portable.

## What the pairing PIN does

The PIN proves that the person at the APP approved this browser. During
pairing the browser creates a private key it can never export; the vault
remembers only the public half. Afterwards every password request must be
signed with that key against a fresh one-time challenge - a copied request
cannot be replayed, and a program that merely finds the local socket/pipe
gets refused: reaching the vault is not permission to read it.

## What lock severs

Closing (= locking) the vault:
  * stops the autofill service - the socket/pipe disappears,
  * invalidates the per-launch transport token,
  * wipes decrypted scratch copies of opened files.
Paired browsers stay REMEMBERED (that's in the encrypted vault), but they can
do nothing until you open and unlock again.

## What SecureVault never does

No network - inbound or outbound - is possible: the program disables sockets
in-process at startup (on Linux only the local, same-machine socket family
stays alive for autofill). No cloud, no telemetry, no OS keychain, no
recovery backdoor.

## Honest limits

Malware running AS YOU on an unlocked machine is outside what any password
manager can fully stop. SecureVault raises the cost: pairing ceremonies,
signed requests, save confirmations, and a keylog-resistant PIN pad.
""", []))

    t.append(("Troubleshooting", f"""\
## "Not connected. Open and unlock the SecureVault app."

The extension cannot reach the vault:
  * Is SecureVault open AND unlocked? (Autofill stops the moment it closes.)
  * Wrong profile? The extension must be installed in the browser profile
    you're using.
  * Restart the browser after first installing the extension.

## "Specified native messaging host not found"

The browser has no registration for the relay:
  * Run Tools > Set up browser autofill... in SecureVault - it writes the
    host manifests and shows where.
  * {'Chrome/Edge read the registration from HKCU; re-run the wizard after moving the app.' if IS_WINDOWS else 'System-wide manifests live in /etc/chromium, /etc/opt/chrome and /etc/opt/edge (installed by the package); per-user ones in ~/.config/<browser>/NativeMessagingHosts.'}

## Extension ID mismatch

Pairing/fill fails and the host log says "caller not allowed", or the wizard
warns the ID differs. The allowed extension ID is pinned; if your browser
shows a DIFFERENT ID under the extension:
  * You loaded a copy of the extension folder, not the shipped one - load
    exactly:
  $  {extension_dir()}
  * Or run Tools > Set up browser autofill... and on the "Confirm the
    extension ID" page paste the ID the browser shows, then "Use this ID".

## "No pairing window is open"

The PIN prompt in the extension only works while the app's "Pair a browser"
window is showing. Click Pair a browser first, then type the PIN within its
countdown.

## Wrong PIN / window burned

Three wrong attempts close the window. Click "Pair a browser" again for a
fresh PIN.

## Autofill fills nothing on a site

The vault matches by domain. Check the entry's URL field: "bank.example.com"
matches "https://bank.example.com/login". Subdomains of the same site match;
unrelated domains never do (a page cannot ask for another site's logins).
""", []))

    return t


# ------------------------------------------------------------------ viewer
class HelpDialog(tk.Toplevel):
    def __init__(self, master, topic=None):
        super().__init__(master)
        svtheme.ensure(self)
        self.title("SecureVault - Help")
        self.configure(bg=TH.bg)
        self.geometry("880x600")
        self.minsize(640, 420)

        head = ttk.Frame(self, padding=(14, 12, 14, 8)); head.pack(fill="x")
        ttk.Label(head, text="SecureVault Help", font=(UI, 13, "bold")).pack(side="left")
        svtheme.beam(self).pack(fill="x")

        pan = ttk.PanedWindow(self, orient="horizontal")
        pan.pack(fill="both", expand=True, padx=8, pady=(8, 0))

        self._topics = _topics()
        left = ttk.Frame(pan)
        self.list = ttk.Treeview(left, show="tree", selectmode="browse")
        self.list.pack(fill="both", expand=True)
        for i, (title, _b, _a) in enumerate(self._topics):
            self.list.insert("", "end", iid=str(i), text=title)
        self.list.bind("<<TreeviewSelect>>", self._on_select)
        pan.add(left, weight=1)

        right = ttk.Frame(pan)
        self.txt = svtheme.text(right, wrap="word", font=(UI, 10), padx=12, pady=10)
        vs = ttk.Scrollbar(right, orient="vertical", command=self.txt.yview)
        self.txt.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        self.txt.pack(side="left", fill="both", expand=True)
        self.txt.tag_configure("h", font=(UI, 12, "bold"), spacing1=10, spacing3=4,
                               foreground=TH.accent)
        self.txt.tag_configure("mono", font=(MONO, 10))
        pan.add(right, weight=4)

        self.actions = ttk.Frame(self, padding=(10, 8)); self.actions.pack(fill="x")

        self.bind("<Escape>", lambda _e: self.destroy())
        want = 0
        if topic:
            for i, (title, _b, _a) in enumerate(self._topics):
                if topic.lower() in title.lower():
                    want = i; break
        self.list.selection_set(str(want))
        self.after(60, lambda: pan.sashpos(0, 220))

    def _on_select(self, _e=None):
        sel = self.list.selection()
        if not sel:
            return
        title, body, actions = self._topics[int(sel[0])]
        self.txt.configure(state="normal")
        self.txt.delete("1.0", "end")
        for line in body.splitlines():
            if line.startswith("## "):
                self.txt.insert("end", line[3:] + "\n", "h")
            elif line.startswith("  $"):
                self.txt.insert("end", "  " + line[3:].strip() + "\n", "mono")
            else:
                self.txt.insert("end", line + "\n")
        self.txt.configure(state="disabled")
        for w in self.actions.winfo_children():
            w.destroy()
        for label, cb in actions:
            ttk.Button(self.actions, text=label,
                       command=lambda c=cb: self._run_action(c)).pack(side="left", padx=3)

    def _run_action(self, cb):
        try:
            if not cb():
                messagebox.showinfo("SecureVault", "Could not open the folder - "
                                    "the path is shown in the help text.", parent=self)
        except Exception as ex:
            messagebox.showerror("SecureVault", str(ex), parent=self)


_open = None

def show(master, topic=None):
    """Open (or focus) the help window. `topic` picks the initial page by a
    substring of its title, e.g. 'pairing' or 'extension'."""
    global _open
    try:
        if _open is not None and _open.winfo_exists():
            _open.lift(); _open.focus_set()
            if topic:
                for i, (title, _b, _a) in enumerate(_open._topics):
                    if topic.lower() in title.lower():
                        _open.list.selection_set(str(i)); break
            return _open
    except Exception:
        pass
    _open = HelpDialog(master, topic=topic)
    return _open


if __name__ == "__main__":
    root = tk.Tk(); root.withdraw()
    svtheme.apply(root, svtheme.load_pref())
    d = show(root)
    d.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()
