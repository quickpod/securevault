# SecureVault - Detailed Usage

This is the long-form guide. For a one-page overview see the top-level
[`README.md`](../README.md); to build the `.exe` yourself see [`BUILD.md`](BUILD.md).

- [The vault](#the-vault)
  - [Creating a vault](#creating-a-vault)
  - [Choosing & switching the vault location](#choosing--switching-the-vault-location)
  - [The three-factor unlock](#the-three-factor-unlock)
  - [TOTP enrollment](#totp-enrollment)
  - [Everyday file use](#everyday-file-use)
  - [Opening files in place](#opening-files-in-place)
  - [The password manager](#the-password-manager)
  - [Import passwords from your browser](#import-passwords-from-your-browser)
  - [Command line](#command-line)
- [Browser autofill setup](#browser-autofill-setup)
  - [The setup wizard (recommended)](#the-setup-wizard-recommended)
- [The Windows hardening scripts](#the-windows-hardening-scripts)
- [Uninstall](#uninstall)

---

## The vault

### Creating a vault

Launch the GUI - `SecureVault.exe` from a release, or `py src\sv_app.py` from source.
With no vault present it offers to **create one**. You choose:

1. A **master password** (typed).
2. A **6-digit PIN** (clicked on the on-screen keypad).

It then shows a **TOTP enrollment secret / `otpauth://` URI once** - add it to your
authenticator app right away (see [TOTP enrollment](#totp-enrollment)).

> **There is no recovery and no backdoor.** The container stores only a random salt and
> AES-GCM ciphertexts; the password/PIN are SHA-256 hashed at the input box and stretched
> with scrypt into the key. Nothing reversible is written to disk. Write your password +
> PIN down somewhere safe and offline, and keep a copy of the TOTP secret.

The container lives in `SecureVault.dat`. You choose **where** (see the next section);
recovery aid: setting `SECUREVAULT_TOTP_SECRET` when creating a vault seeds a known TOTP
secret instead of a random one, so you can re-enroll the same code on a new device.

### Choosing & switching the vault location

The vault file can live **anywhere** - a synced/backup folder, an external drive, wherever
you like - and SecureVault remembers your choice between runs.

- **First launch (GUI):** if a previously-used vault still exists, it opens straight away.
  Otherwise a small chooser appears with **Create new vault...** (pick a location and name,
  default `SecureVault.dat`) or **Open existing vault...**, plus a short **Recent vaults**
  list.
- **Switching vaults (GUI):** the **File** menu has **New Vault...**, **Open Vault...** and
  **Open Recent**. Choosing one re-locks the current vault (wiping anything decrypted
  outside it, after warning about unsaved edits) and reopens the window on the new one. The
  current vault's path is shown in the window title.
- **Command line:** every command accepts an optional **`--dat <path>`** (alias
  **`--vault <path>`**), which takes precedence over everything else:

  ```
  SecureVault.exe --dat D:\Vaults\Work.dat list
  SecureVault.exe init --vault "E:\Backup\SecureVault.dat"
  ```

**Precedence**, highest first: `--dat`/`--vault` -> the `SECUREVAULT_DAT` environment
variable -> the last-used vault remembered from a previous run (if the file still exists) ->
the default `SecureVault.dat` next to the program (Windows) or
`~/.local/share/securevault/SecureVault.dat` (Linux, where the program dir is read-only).
Vault files are byte-identical across OSes - copy a `.dat` between Windows and Linux freely.

> **Where the "remembered" location is stored:** a tiny, **non-secret** settings file at
> `%LOCALAPPDATA%\SecureVault\config.json`. It holds only **paths** (the last-used vault and
> a short recent list) - never a password, PIN, TOTP secret, or key. Deleting it just makes
> the app ask which vault to open next time; it never touches your `.dat`.

### The three-factor unlock

Every unlock needs all three factors, and all three are checked **before** the data key is
ever exposed:

1. **Password** - typed into the password box.
2. **PIN** - entered by **clicking a randomized on-screen keypad**. The pad reshuffles
   after every digit, so the PIN never touches the physical keyboard and cannot be captured
   by a software *or* hardware keylogger, or a mouse-position logger.
3. **TOTP code** - the current 6-digit code from your authenticator app.

Before the password box appears, the app runs a **best-effort keylogger / monitoring scan**
and warns if it spots known tools. This is heuristic only (see the limitations in the
README); the click-only PIN pad is the real defense.

### TOTP enrollment

On first run the app displays the enrollment secret and an `otpauth://` URI / QR **once**.
Add it to any standard authenticator: **Google Authenticator, Authy, Aegis, 1Password**,
etc. Codes are RFC 6238, computed locally, with no network. After enrollment you'll need a
live code at every unlock, so keep the enrolled device (and a backup of the secret) safe.

In the password manager, individual logins can also carry their **own** TOTP secret (raw
base32 or a pasted `otpauth://` URI) - handy for sites' 2FA codes, shown live in the UI.

### Everyday file use

Open `SecureVault.exe` and unlock. The GUI is an Explorer-style browser:

- **Folder tree** on the left. The vault stores names like `Documents/2026/tax.pdf`, and
  the tree is built from those paths - click a folder to see it, double-click to descend,
  **Up** to go back.
- **Search box** filters the current folder *and everything beneath it*.
- **Add Files / Add Folder** - added into the folder you are viewing (optionally deleting
  the originals).
- **Extract Selected / Extract All** to a folder you choose (structure preserved).
- **Preview** small text/images **in memory only** - nothing hits disk.
- **Delete** removes a file and **compacts** the container.
- **Verify** re-authenticates every stored file (GCM tag + per-file SHA-256).
- **Change Password / PIN** re-wraps the key; your files are **not** re-encrypted.
- **Tools -> Vault info** shows how much reclaimable "dead space" the container holds.

You can also send files in from Explorer: right-click any file -> **Send to SV (Secure
Vault)** (see [Command line](#command-line) / the Explorer menu).

### Opening files in place

Double-click a file (or select it and press **Open**) and it opens in whatever application
Windows normally uses for that type - Word, Acrobat, Notepad, an image viewer. Underneath:

1. The file is decrypted into a **private per-session scratch directory** under
   `%LOCALAPPDATA%\Temp`, with its ACL reset to your account only.
2. It's handed to its associated app.
3. SecureVault watches for that app to **close**.
4. If you **changed** the file, it asks whether to save the new version back into the vault.
   Answer *No* and the edits are discarded.
5. Either way the decrypted copy is **overwritten with random bytes and deleted**.

How the close is detected, most reliable first:

| Signal | When | Behaviour |
|---|---|---|
| Process handle | The app was started fresh (Notepad, most viewers) | Exact - wiped the moment it exits. |
| File lock | The file went to an already-running instance that locks it (Word, Excel) | Wiped when the lock is released. |
| Neither | Some app took it and never locked it | Stays until you click **"I'm done - close & wipe"** or close the vault. |

Nothing is ever wiped on a timer, so a slow read is never mistaken for a close. An amber
bar lists anything still checked out; closing the vault window wipes everything it
decrypted (after warning about unsaved edits), and an `atexit` hook sweeps up if the
process is killed. Files whose type Windows has no handler for are refused with an offer to
pick an app. Saving an edit **appends** a new encrypted blob and repoints the index rather
than rewriting a multi-GB container; **Delete** later compacts the dead space away.

### The password manager

Open **Passwords** from the main window (works on the already-unlocked vault - no second
prompt). The whole password database is stored as **one encrypted entry** inside the vault.

- The list shows **title / username / domain / strength / 2FA** only - passwords are never
  placed in a widget.
- **Add / Edit / Delete** logins. The Add/Edit dialog has a masked password field with a
  "Show" toggle, a **Generate strong password** button, and a TOTP field (raw base32 or
  `otpauth://`).
- **Copy password / username / TOTP.** Copying a password goes through a **phishing gate**:
  a confirm dialog naming the stored domain. The clipboard **auto-clears** after ~90s
  (30s for TOTP codes).
- **Generate...** - CSPRNG generator; choose length (8-128) and character classes; avoids
  ambiguous characters by default.
- **Audit...** - flags reused, weak (<60 bits), stale (>1 year), and no-2FA entries.
- **Import Chrome CSV...** - previews a Chrome/Edge/Brave export, imports (skipping
  same-username-same-domain duplicates, backfilling missing titles), then **shreds** the CSV.
- **Browsers...** - manage browser autofill pairings (see below): pair a browser (shows the
  one-time PIN) or revoke one.

Passwords keep a **history** (up to 10 prior values) so a rotation doesn't lose the old one.

### Import passwords from your browser

**Tools -> Import passwords from browser...** opens a guided wizard that pulls your saved
logins out of Chrome / Edge / Brave and into the vault. It runs against the **already-open,
unlocked** vault (open a vault first). The steps:

1. **Export instructions.** Pick your browser and follow the exact export steps:
   - **Chrome:** `chrome://password-manager/settings` -> **Settings** -> **Export passwords**
     -> confirm with your Windows account -> save the CSV.
   - **Edge:** `edge://wallet/passwords/settings` (or **Settings -> Profiles -> Passwords**)
     -> **Export passwords** -> save the CSV.
   - **Brave:** `brave://settings/passwords` -> **Export passwords** -> save the CSV.

   > **The exported CSV is PLAINTEXT.** Save it to a folder only your Windows account can
   > read; **never** onto a removable/network drive or a synced folder (OneDrive/Dropbox).
   > The wizard securely shreds it after importing.

2. **Pick the CSV.** A file picker (`.csv` filter). The wizard then shows a summary - how
   many credentials were found and a small sample of **titles/usernames/domains only**
   (never passwords) - plus how many rows look blank/skippable.
3. **Import.** Choose whether to **skip duplicates** (same username on the same domain;
   on by default), then import. It reports how many were added and how many skipped.
4. **Shred.** Securely delete the plaintext CSV (checked by default). If you exported into a
   synced folder, remember to purge it there **and** empty the online trash.
5. **Done.** Imported logins are tagged **`chrome-import`** so you can find and review them
   in the password manager (and run **Audit...** to catch reused/weak entries).

The same thing is available from the password manager's **Import Chrome CSV...** button and
from the CLI (`pw import-chrome`); the wizard just walks you through the export and shred
around it.

### Command line

The same `SecureVault.exe` (or `py src\sv_app.py <args>`) is also a CLI:

```
SecureVault.exe init                       # create the vault
SecureVault.exe add     <path> [...]       # encrypt in, delete originals
SecureVault.exe addkeep <path> [...]       # encrypt in, keep originals
SecureVault.exe list
SecureVault.exe get     <name> [dest]
SecureVault.exe extract <destdir>
SecureVault.exe remove  <name>
SecureVault.exe verify
SecureVault.exe passwd                     # change password / PIN

SecureVault.exe register                   # add the Explorer right-click menu (HKCU)
SecureVault.exe unregister                 # remove it
SecureVault.exe shellstatus                # is it installed, and pointing where?

SecureVault.exe pw <list|show|reveal|copy|add|edit|rm|gen|totp|audit|import-chrome> ...
SecureVault.exe scan                       # heuristic keylogger/monitoring scan

SecureVault.exe --dat <path>  <cmd> ...     # use a specific vault (alias --vault)
```

`--dat`/`--vault` may appear anywhere on the line and applies to every command (including
`init`), overriding `SECUREVAULT_DAT`, the remembered location, and the default. See
[Choosing & switching the vault location](#choosing--switching-the-vault-location).

For scripting, `SECUREVAULT_PW` / `SECUREVAULT_PIN` / `SECUREVAULT_TOTP` can supply the
factors (avoid on shared machines). The **Explorer right-click menu** is registered per-user
under `HKCU\Software\Classes`; run `register` again after moving the exe, rebuilding
Windows, or resetting your profile, and it repoints every verb.

---

## Browser autofill setup

Autofill is **local-only**: the Chrome/Edge MV3 extension talks to a native-messaging host,
which relays to the **running, unlocked** vault - over a Windows named pipe, or on Linux over
a per-user UNIX socket in `$XDG_RUNTIME_DIR/securevault/` (0700 directory, 0600 socket, gone
at logout). The host holds no keys and can decrypt nothing; if the app is closed or locked,
every request fails. The same PIN pairing and per-request signatures apply on both OSes.

The in-app **Help menu (F1)** carries the same walkthroughs - "Browser autofill & pairing"
and "Install the extension" - with an *Open extension folder* button.

### The setup wizard (recommended)

Rather than run the steps below by hand, use **Tools -> Set up browser autofill...** (also
offered right after you create a new vault). The wizard:

1. **Explains** that autofill is local-only and works only while the vault is open+unlocked.
2. **Detects** installed Chromium browsers (Chrome, Edge, Brave) and lets you tick which to
   set up (found ones ticked by default; you can proceed even if none are detected).
3. **Installs the bridge** - runs the same key/ID + file generation as step 1 below, then
   registers the native host (HKCU) and, if elevated, allowlists the extension (HKLM policy).
   A single browser failing is reported inline and never aborts the rest.
4. **Guides loading** the unpacked extension (with an **Open extension folder** button and a
   **Copy** button for the path, since browsers can't be scripted into "Load unpacked").
5. **Confirms the extension ID** - shows the deterministic ID SecureVault pins, and lets you
   paste the one the browser actually shows; on confirm it rewrites the native host's
   `allowed_origins` to match.
6. **Summarizes** what was configured per browser, how to test, and how to remove it later.

### Linux / Quick OS

On Linux the pieces are pre-wired by the packages:

- **Quick Browser ships the extension pre-installed** - nothing to load. Open the vault,
  **Passwords -> Browsers... -> Pair a browser**, type the PIN into the extension popup, done.
- The **native-messaging host manifests are installed system-wide** by the
  `quickopen-securevault` package for Quick Browser/Chromium (`/etc/chromium/native-messaging-hosts/`),
  Google Chrome (`/etc/opt/chrome/native-messaging-hosts/`) and Microsoft Edge
  (`/etc/opt/edge/native-messaging-hosts/`), all pointing at
  `/opt/quickopen/securevault/nativehost/svhost`.
- **Chrome/Edge manual install (developer mode, once):** open `chrome://extensions` /
  `edge://extensions`, enable **Developer mode**, click **Load unpacked** and select

  ```
  /opt/quickopen/securevault/extension
  ```

  The manifest carries a pinned key, so the browser assigns the same extension ID the host
  manifests already allow - pairing works with no further setup.
- The wizard (**Tools -> Set up browser autofill...**) additionally writes *per-user* host
  manifests (`~/.config/<browser>/NativeMessagingHosts/`) for Chromium/Brave or any browser
  the system manifests missed.
- The autofill endpoint is `$XDG_RUNTIME_DIR/securevault/autofill.sock`, created only while
  the vault is open and unlocked, with the same HMAC-token handshake as the Windows pipe.

The manual **Windows** equivalent is:

**1. Generate the bridge config files.** From the install/source dir:

```powershell
py src\svautofill_setup.py apply --root %LOCALAPPDATA%\SecureVault
```

This generates a stable extension signing key, writes the extension `manifest.json` `key`,
the native-host launcher (`nativehost\svhost-launcher.bat`), the native-host manifest
(`nativehost\com.securevault.autofill.json`) with the derived extension origin, and the
host's own allow-list at `%LOCALAPPDATA%\SecureVault\svhost_allowed.json`. Run
`... svautofill_setup.py status` to print the derived extension ID.

**2. Register the host in the browsers.** From an elevated PowerShell (the HKLM policy
allowlist step needs elevation; the HKCU host registration does not):

```powershell
.\Install-BrowserFill.ps1 -Apply
```

This registers `com.securevault.autofill` under
`HKCU\Software\Google\Chrome\NativeMessagingHosts` (and the Edge equivalent) and allowlists
the extension past the Harden-Chrome blocklist.

**3. Load the unpacked extension** (browsers can't be scripted into this):

1. Open `chrome://extensions` (and/or `edge://extensions`) and enable **Developer mode**.
2. **Load unpacked** -> select the `extension` folder (e.g. `%LOCALAPPDATA%\SecureVault\extension`).
3. Confirm the extension ID matches the one `svautofill_setup.py status` /
   `Install-BrowserFill.ps1` printed.

> **On the checked-in template files:** the extension `manifest.json` ships with a pinned
> `key` (the project's public signing key), so on Linux every install derives the same
> extension ID and the packaged host manifests match out of the box. On Windows the
> installer/wizard still runs `svautofill_setup.py apply`, which generates a fresh per-machine
> key/ID and rewrites the manifest + `allowed_origins` together - both flows keep the IDs
> lined up; the Windows `nativehost` template's placeholder origin
> (`chrome-extension://EXTENSION_ID_AFTER_LOAD/`) is replaced by that step.

**4. Pair a browser.** In the vault: **Passwords -> Browsers... -> Pair a browser**. The app
shows a one-time 6-digit PIN (120s window). In the browser's SecureVault popup, enter that
PIN. Pairing is **app-initiated and unphishable** (the PIN comes *from* the app, never into
it). The browser generates a non-extractable ECDSA P-256 key; each privileged request is
signed over a fresh, single-use challenge bound to the operation and origin. You can
**revoke** a browser at any time from the same dialog - it stops filling immediately.

Autofill then offers matching logins on login pages, suggests known usernames/emails on
signups, can generate strong passwords, and prompts to save/update - all confirmed in the
app. **It only works while SecureVault is open and unlocked** (window or background mode).

**Bookmarks backup & restore (favorites sync).** A paired browser's bookmarks are backed
up into the **encrypted vault** - on pairing and whenever they change (debounced), via the
same signed, challenge-bound ops as passwords. Pair a fresh/reinstalled browser and, if it
is empty while the vault holds a backup, the popup offers to **restore** (user-confirmed:
*Merge* dedupes by URL within its folder; *Replace all* clears the browser first - nothing
is silent). An empty browser can never overwrite a real backup. Status lives in the popup
("Bookmarks: N in vault ... M in this browser") and in the app's Browsers window
("Browser data", with a delete-backup control). Works identically for the bundled Quick
Browser extension and manual Chrome/Edge installs, Windows and Linux.

Day-to-day, in the browser:

- The dropdown is keyboard-first (arrows / Enter / Escape), follows the page's light/dark
  scheme, and carries the SecureVault mark so it can't be mistaken for a site's own UI.
- A small **vault badge inside password fields** reopens the menu after it was dismissed.
- The toolbar **popup** live-updates (unlock the vault and it flips to "connected" by
  itself), distinguishes *app not running* (offers **Open SecureVault**) from *vault
  locked*, shows the current site's saved-login count, and has **Fill on this page**,
  **Generate password** (copies it) and **Open vault** actions. The PIN box is digits-only
  and auto-pairs on the 6th digit.

---

## Background mode (tray)

Closing the window with an open vault asks: **Run in background** or **Close & lock**
(with a *remember my choice* box; change it later in **Tools -> Preferences**). Background
mode is what keeps browser autofill available while no window is on screen:

- The tray icon IS the state: an **open blue padlock** = unlocked (autofill available), a
  **closed grey padlock** = locked; it switches instantly, including on auto-lock. Windows
  notification area; on Linux/Quick OS a Plasma StatusNotifier. Plasma may put a new icon
  behind the panel's expand arrow (^) - pin it via Configure System Tray > Entries if you
  want it always visible.
- **Open SecureVault** brings the window back. **Lock now** locks immediately: the autofill
  endpoint disappears, the transport token is destroyed, and decrypted scratch copies are
  wiped - identical to closing the window. **Quit** locks and exits.
- **Single-instance:** launching SecureVault while a copy is already running (visible,
  trayed, or locked in the tray) raises the running one - never an error, never a second
  instance. The guaranteed way back to a background vault even if the tray is hidden.
- **Start at login:** once a vault has been opened on a machine, SecureVault starts at
  login **locked, in the tray** - no window, no prompt; autofill is one unlock away. An
  explicit preference (Tools > Preferences) turns it off; it is never enabled on a machine
  where no vault has ever been opened. Linux: `~/.config/autostart/` entry (stops firing
  automatically if the package is removed); Windows: per-user HKCU Run value (removed by
  `uninstall.ps1`).
- **Auto-lock:** a trayed vault locks itself after an idle period (default 15 minutes;
  autofill requests count as activity; configurable 1-240 minutes, never "off").
- The tooltip/menu never show paths, entry names or secrets.

---

## The Windows hardening scripts

These are **standalone** PowerShell scripts in the repo root, independent of the vault. All
follow the same convention:

- **No switch** = read-only **status** (what's configured, and what's actually in effect).
- **`-Apply`** = make the change (most require an **elevated** session).
- **`-Revert`** (or a dedicated `Revert-*.ps1`) = undo it.
- Where a change could lock you out remotely, an optional **`-ArmDeadMan N`** schedules an
  automatic revert in N minutes unless you `-Disarm` first.

> **Run `New-RestorePoint.ps1` first** (elevated). It enables System Restore, sizes shadow
> storage, and takes a checkpoint - your safety net before anything else.

| Script | What `-Apply` changes | Elevated? | Revert |
|---|---|---|---|
| `New-RestorePoint.ps1` | Enables System Restore on C:, 10% shadow storage, removes the 24h throttle, takes a checkpoint. | Yes | It *is* the revert (System Restore / `rstrui.exe`). |
| `Harden-Laptop.ps1` | Default-deny inbound firewall; disables LLMNR/NBT-NS/mDNS, SMBv1, inbound-exposing services; LSASS PPL; WDigest off; AutoRun off; UAC; BitLocker check. | Yes | `Revert-NetworkHardening.ps1` (network parts). Non-network changes aren't scripted back. |
| `Fix-Gaps.ps1` | Disables stale/Guest/built-in-admin accounts; password policy; BitLocker pre-boot PIN policy + recovery-key export; removes Java; DoH template table. | Yes | `Revert-FixGaps.ps1` (`-RepairDns` / `-BitLocker` / `-Accounts` / `-All`). **Java removal is not reversible.** |
| `Set-EncryptedDns.ps1` | Points the adapter at DoH-capable public resolvers (1.1.1.1 / 8.8.8.8), self-verifying with auto-rollback. | Yes | `-Revert` (hands DNS back to DHCP; `-Full` also resets template flags). Optional dead-man. |
| `Set-PrivateDoh.ps1` | Points the adapter at **your** DoH endpoints only; installs a watchdog that swaps to public resolvers if yours go dark. Endpoint URLs come from a `-DohFile` you keep off any synced folder. | Yes | `-Revert` (back to public DoH) / `-Revert -ToDhcp` (captive-portal escape). Dead-man switch. |
| `Block-AllInbound.ps1` | Sets `AllowInboundRules=False` on all firewall profiles - blocks **every** inbound, even allowed apps. | Yes | `-Revert` (restores saved state). Dead-man switch. |
| `Block-HpSmartInternet.ps1` | Outbound firewall block rules so HP Smart reaches only the LAN. | Yes (status/`-WhatIf` unelevated) | `-Revert` (deletes the rule group). |
| `Reduce-IdleFootprint.ps1` | Stops idle background apps (Edge background/boost, Copilot/Widgets/Search auto-launch; optional SearchHost firewall block, Widgets removal). Optional `-IncludeOneDrive/-Discord/-Firefox`, `-StopNow`. | Yes | `-Revert` (restores saved values, removes the fw rule). |
| `Remove-StoreBloat.ps1` | Removes + deprovisions unused Store (MSIX) apps. | Yes (per-user removal works unelevated) | `-Revert` (best-effort re-register; some need a manual Store reinstall). |
| `Disable-DeviceAssociation.ps1` | Disables DeviceAssociationService so dasHost stops holding UDP 3702 (takes effect after reboot). | Yes | `-Revert` (Automatic + start; immediate). |
| `Set-HpDoctorManual.ps1` | HP Print/Scan Doctor service Automatic -> Manual, and stops it. | Yes | `-Revert` (Automatic + start). |
| `Set-OpenWifiManual.ps1` | Every saved **open** Wi-Fi profile set to manual connect (stops silent auto-join / evil-twin). Profiles kept. | Yes | `-Revert` (back to auto). |
| `Harden-Chrome.ps1` | Chrome enterprise policies: Safe Browsing, HTTPS-only, TLS floor, content/hardware guards, telemetry off, extension blocklist, updater. | Yes (status unelevated) | `-Revert` (deletes the policy keys -> stock defaults). `-Disarm` cancels dead-man. **`-RemoveTrustWallet` is separate and irreversible.** |
| `New-IosDohProfile.ps1` | Builds an iOS `.mobileconfig` pointing an iPhone at your DoH resolver system-wide. Output contains a bearer token - keep it off any synced folder and delete it from the phone after installing. | **No** | No switch - remove the profile on the iPhone. |
| `Backup-SecureVault.ps1` | Registers an hourly scheduled task copying your vault folder to up to three destinations (chained robocopy, **never** `/MIR` or `/PURGE`, volume-pinned USB). Edit `$Source` and the destinations to match your setup. | Not enforced (task runs as you) | `-Revert` (removes the task; leaves backups). |
| `Install-BrowserFill.ps1` | Registers the autofill extension + native host in Chrome/Edge and allowlists it. | HKCU part unelevated; HKLM allowlist needs elevation | `-Revert` (removes registration + allowlist). |
| `Check-Status.ps1` | Read-only health check of all the above (DNS, DoH, inbound firewall, services, accounts, dead-man tasks). | Elevated recommended for the full picture | N/A (read-only). |

Modular scripts stash their last-good state under `C:\SecureVault\Backups\` so `-Revert`
can restore it. When DNS trouble runs deeper than a single script, the scripts point you at
`Revert-FixGaps.ps1 -RepairDns` as the service-level recovery of last resort.

---

## Uninstall

The repo's [`uninstall.ps1`](../uninstall.ps1) does a clean removal and prints every step.
It is idempotent (safe to run twice) and **never deletes your `SecureVault.dat`**.

```powershell
.\uninstall.ps1                 # full removal
.\uninstall.ps1 -WhatIf         # show what it would do, change nothing
.\uninstall.ps1 -KeepHardening  # skip the Revert-* passes (only remove app integration)
```

What it does:

1. **Reverts hardening** it can, best-effort: calls `Install-BrowserFill.ps1 -Revert`,
   `Backup-SecureVault.ps1 -Revert`, and (unless `-KeepHardening`) the network/DNS/idle
   reverts. Anything already reverted is a no-op.
2. **Removes the Explorer shell integration** - deletes the three HKCU keys
   `HKCU:\Software\Classes\*\shell\SecureVaultAdd`,
   `HKCU:\Software\Classes\Directory\shell\SecureVaultAdd`, and
   `HKCU:\Software\Classes\Directory\Background\shell\SecureVault` (the same keys
   `src\install_shell_integration.ps1` and `SecureVault.exe register` create). If a
   `SecureVault.exe` is present it also runs `SecureVault.exe unregister`.
3. **Removes the native-messaging host registration** - deletes the registry values
   `HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.securevault.autofill` and
   `HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.securevault.autofill`.
4. **Deletes the install dir** `%LOCALAPPDATA%\SecureVault` (source, extension, native host,
   and the generated `svhost_allowed.json` / signing key). Pass `-KeepData` isn't needed for
   the vault - your `.dat` is not stored here unless you put it here; move it out first if it
   is.

**Do by hand:** remove the unpacked extension from `chrome://extensions` /
`edge://extensions` (browsers can't be scripted out of this), and delete any
`.mobileconfig` you installed on an iPhone.
