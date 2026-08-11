# SecureVault

A standalone, password-protected encrypted file vault. Everything lives in **one
container file** (`SecureVault.dat`) that you can bundle next to the program and
copy anywhere — let any cloud-sync or backup tool copy it offsite and it is
useless to anyone without your master password.

## What you get

| File | Purpose |
|------|---------|
| `SecureVault.exe` | The standalone program (no Python needed). Double-click = GUI browser. |
| `SecureVault.dat` | Your encrypted vault. The only file that holds your data. Back this up. |
| `securevault.py` | Source: the container format + crypto + CLI. |
| `svgui.py` | Source: the Explorer-style GUI (folder tree + file list). |
| `svopen.py` | Source: open-in-place — decrypt to scratch, launch, wipe on close. |
| `svshell.py` | Source: the right-click menu, registered by the exe itself. |
| `sv_app.py` | Source: the unified entry point that becomes the .exe. |
| `install_shell_integration.ps1` | Optional: does the same as `SecureVault.exe register`. |
| `selftest.py` | Self-test proving the format round-trips and detects tampering. |

## Three-factor unlock

Opening the vault requires all three:

1. **Password** — typed.
2. **6-digit PIN** — entered by **clicking a randomized on-screen keypad** (the pad
   reshuffles after every digit), so the PIN is never typed and cannot be keylogged.
3. **Authenticator (TOTP) code** — a 6-digit code from Google Authenticator / Authy
   / Aegis / 1Password, enrolled on first run.

Before the password box appears, the app runs a **best-effort keylogger scan** and
warns if it spots known monitoring software (heuristic only — see limitations).

## First run

Double-click `SecureVault.exe`. With no vault yet it offers to **create one**: you
set the password and PIN, and it shows a **TOTP enrollment secret / otpauth URI
once** — add it to your authenticator app immediately. There is no recovery, no
backdoor, no reset for the password or PIN. Write them down somewhere safe and
offline, and keep a backup of the TOTP secret.

Recovery/backup: setting `SECUREVAULT_TOTP_SECRET` when creating a vault seeds a
known TOTP secret instead of a random one (useful to re-enroll the same code on a
new device).

## Everyday use

- **Right-click any file → "Send to SV (Secure Vault)"** — the file is encrypted
  into the vault and the original is deleted.
- **Double-click `SecureVault.exe`** — the browser opens:
  - a **folder tree** on the left, exactly like Explorer. The vault stores names
    such as `Documents/2026/tax.pdf`, and the tree is built from those paths —
    click a folder to see its contents, double-click a folder row to descend,
    **Up** to go back.
  - a **search box** that filters the current folder *and everything beneath it*
  - **Add Files / Add Folder** — added into the folder you are viewing
  - **Extract Selected / Extract All** to a folder you choose (selecting a
    folder extracts everything under it, keeping the structure)
  - **Preview** small text/images (decrypted in memory only — nothing hits disk)
  - **Delete** removes a file from the vault and compacts the container
  - **Verify** re-authenticates every stored file
  - **Change Password** re-wraps the key; your files are not re-encrypted

## Opening a file directly

**Double-click a file** (or select it and press **Open**) and it opens in whatever
application Windows normally uses for that type — Word, Acrobat, Notepad, an image
viewer. You do not have to extract it, find it, and remember to shred it afterwards.

What happens underneath:

1. The file is decrypted into a **private scratch directory** under
   `%LOCALAPPDATA%\Temp`, created per session, with its ACL reset to your account
   only.
2. It is handed to its associated application.
3. SecureVault watches for that application to **close**.
4. If you **changed** the file, it asks whether to save the new version back into
   the vault. Answer *No* and your edits are discarded.
5. Either way the decrypted copy is **overwritten with random bytes and deleted**.

Anything still checked out is listed in an amber bar at the bottom of the window
with an **"I'm done — close & wipe"** button, and closing the vault window wipes
everything it decrypted — after warning you about unsaved edits. If the process
is killed instead, an `atexit` hook makes the same sweep.

**How the close is detected**, in order of reliability:

| Signal | When | Behaviour |
|---|---|---|
| Process handle | The app was started fresh (Notepad, most viewers) | Exact. Wiped the moment it exits. |
| File lock | The file went to an already-running instance that locks it (Word, Excel) | Wiped when the lock is released. |
| Neither | Some app took the file and never locked it | Stays until you click **"I'm done"** or close the vault. |

Nothing is ever wiped on a timer, so a slow read is never mistaken for a close —
the cost of that choice is the third row, where you have to say when you are done.

Files whose type Windows has no handler for are **refused** with an offer to pick
an app, rather than letting the shell throw its modal "How do you want to open
this file?" picker on top of the vault window (which would freeze it).

Saving an edit back **appends** the new version and repoints the index; the old
encrypted blob is left as dead space rather than rewriting a multi-GB container.
**Tools → Vault info** shows how much is reclaimable, and any **Delete** compacts
it away.

## Command line (same .exe)

```
SecureVault.exe init
SecureVault.exe add     <path> [...]     # encrypt in, delete originals
SecureVault.exe addkeep <path> [...]     # encrypt in, keep originals
SecureVault.exe list
SecureVault.exe get     <name> [dest]
SecureVault.exe extract <destdir>
SecureVault.exe remove  <name>
SecureVault.exe verify
SecureVault.exe passwd

SecureVault.exe register                 # add the Explorer right-click menu
SecureVault.exe unregister               # remove it
SecureVault.exe shellstatus              # is it installed, and pointing where?
```

## The Explorer right-click menu (and moving to a new machine)

The exe registers its own menu — there is nothing else to install and no admin
rights are needed:

```
SecureVault.exe register
```

That writes three verbs under `HKCU\Software\Classes`:

| Right-click on | Menu entry |
|---|---|
| any file | Send to SV (Secure Vault) |
| a folder | Send folder to SV (Secure Vault) |
| a folder backdrop | Open Secure Vault |

**Run `register` again after** rebuilding Windows, moving to a new machine,
restoring a profile, or just moving `SecureVault.exe` to a different folder — it
rewrites every verb to point wherever the exe is now. The keys are per-user, so
a profile reset silently removes them; if the menu disappears, that is why.

`shellstatus` tells you whether the installed menu points at *this* copy, and the
GUI says so in its status bar and under **Tools**. The keys contain only the path
to the program — no vault data and nothing secret.

Environment overrides: `SECUREVAULT_DAT` (container path — default is next to the
exe), `SECUREVAULT_PW` (password, for scripting — avoid on shared machines).

## Security model

- **Encryption**: AES-256-GCM (authenticated) per file, fresh 96-bit nonce each.
- **Password & PIN never stored / not recoverable**: the container records only a
  random salt and AES-GCM ciphertexts. The password and PIN are combined and
  **SHA-256 hashed at the input box** (raw wiped immediately), then stretched with
  **scrypt** into the key. Neither the password, the PIN, nor any reversible form of
  them is ever written to disk — verified: their bytes do not appear in the `.dat`,
  and the one-way `SHA-256 → scrypt` chain cannot be reversed.
- **Key**: a random 256-bit data key, itself wrapped with a key derived (via
  **scrypt**, N=32768, r=8, p=1) from the password hash. Changing the password
  re-wraps the data key without re-encrypting your files. The password itself is
  not recoverable from the container (scrypt is one-way).
- **Filenames hidden**: the file index (names, sizes, sources, hashes) is stored
  **encrypted** inside the container, so the `.dat` leaks neither contents nor names.
- **Tamper-evident**: GCM tags + per-file SHA-256 mean any modification to the
  container is detected on read (`verify`).
- **OS-independent**: security rests entirely on your password. **No secret** is
  ever placed in Windows DPAPI, a keychain, the TPM, the registry, a filesystem
  ACL, or the OS / CA **certificate store**. Move the `.dat` to any OS and it
  behaves identically. Two OS features are used, neither holding anything secret
  and neither load-bearing for the vault's security:
  - the **registry**, for the Explorer menu — only the exe's path, only when you
    run `register`;
  - a **filesystem ACL** on the open-in-place scratch directory, as one more
    layer over plaintext that is already inside your own profile.
- **No network, enforced**: the program imports no networking code, and at startup
  it **disables sockets**, so it can make **no inbound or outbound connection of
  any kind** even via a dependency. It is fully offline.

- **PIN keypad**: click-only, randomized every keypress — defeats software and
  hardware keyloggers and mouse-position loggers for the PIN factor.
- **TOTP**: RFC 6238, computed locally, no network. A possession factor enrolled
  in your authenticator app.

### Honest limitations
- **Unlocked-state exposure**: while the vault is open and you view/extract a file,
  that plaintext exists in memory (and on disk if extracted). No userspace program
  can hide decrypted data from kernel-level malware **at the moment you decrypt it**.
  The strong, unconditional guarantee is for data **at rest**: the `.dat` and its
  offsite backup are worthless without password + PIN.
- **Open-in-place writes plaintext to disk, by design.** This is the one feature
  that does. While a file is open its decrypted contents sit in the scratch
  directory, readable by anything running as you. Preview stays memory-only if
  you want to look without that.
- **Wiping is best effort, not erasure.** The scratch copy is overwritten with
  random bytes before deletion, but on an **SSD** wear-levelling and the FTL can
  leave the original blocks readable to a forensic tool. Full-disk encryption
  (BitLocker) is what actually protects those remnants — which is a reason to
  have a **pre-boot PIN**, since TPM-only unlocks the disk for anyone who powers
  the laptop on.
- **The app you open the file with is a normal program.** It can be online, it
  can auto-save elsewhere, and it may leave its own copies — Office temp files,
  a "recent documents" entry, a thumbnail in the shell cache. SecureVault wipes
  *its* scratch copy; it cannot chase a copy another application decided to make.
  SecureVault's own "no network, sockets disabled" guarantee covers SecureVault,
  not the viewer it hands your file to.
- **Save-back trusts the file on disk.** If something else modified the scratch
  copy while it was open, saving back stores that. The prompt tells you the file
  changed; it cannot tell you *who* changed it.
- **Keylogger scan is heuristic**: it matches known-tool signatures and cannot
  detect a novel or kernel/hardware logger. The click-only PIN is the real defense,
  not the scan.
- **TOTP on a local file**: it is a genuine possession gate at unlock, but it cannot
  add cryptographic secrecy against an attacker who already holds your `.dat` **and**
  your password **and** PIN — the enrolled secret is stored wrapped by those, so such
  an attacker could extract it. It defends the normal case: possession of your
  enrolled device, and resistance to an observed/guessed password or PIN.

## Backup

Keep `SecureVault.dat` inside a folder your backup or cloud-sync tool copies
offsite. That tool ships the encrypted container offsite; the remote copy is
unreadable without your password.
To restore on another machine: copy `SecureVault.exe` + `SecureVault.dat` together,
run the exe, enter your password.

## Rebuild the exe from source

```
pip install cryptography pyinstaller
pyinstaller --onefile --windowed --name SecureVault --collect-submodules cryptography ^
  --hidden-import svgui --hidden-import svopen --hidden-import svshell ^
  --hidden-import svsec --hidden-import svtotp sv_app.py
```

The `--hidden-import` flags are there because the GUI and the shell verbs are
imported lazily inside functions; without them a build can silently omit them and
you only find out when a menu item throws.

Then copy `dist\SecureVault.exe` next to your `.dat` and run
`SecureVault.exe register` so the Explorer menu points at the new build.

Run `python selftest.py` first — it covers the container format, the folder tree,
the open/edit/save-back/wipe cycle, and the registry verbs.
