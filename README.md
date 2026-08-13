# SecureVault

**A local-only, three-factor encrypted vault and Windows hardening toolkit. No cloud, ever.**

SecureVault is a standalone Windows privacy and security suite in two independent parts:

1. **An encrypted vault** - one container file (`SecureVault.dat`) holding your files
   *and* your passwords, protected by **three factors**: a typed master password, a
   6-digit PIN entered on a **randomized on-screen keypad** (never typed, so it cannot
   be keylogged), and a **TOTP** authenticator code. Includes a built-in password
   manager, TOTP generator, "open files in place" workflow, and an optional
   **local-only browser autofill** bridge (Chrome/Edge MV3 extension + native host).
2. **A set of Windows hardening scripts** - standalone PowerShell scripts that lock the
   machine down (encrypted DNS, inbound firewall, idle-footprint reduction, Chrome
   hardening, and more), each with a matching **revert** path and a read-only status mode.

Everything runs **entirely offline**. The vault program imports no networking code and
disables sockets at startup, so it can make no inbound or outbound connection of any
kind - even through a dependency. The only secret is the one you type.

> This is an AI-built project published on [QuickOpen](https://quickopen.dev).

---

## Who it is for

- Anyone who wants a password/file vault that lives **only on their machine** - no
  account, no sync server, no vendor who can be breached or subpoenaed.
- Laptop users who travel and want a **repeatable Windows hardening baseline** they can
  apply and fully revert.
- People who want browser autofill without trusting a cloud password manager.

## Why use it

- **Local-only, no cloud.** Nothing leaves the device. Sockets are disabled in-process.
- **Three-factor unlock.** Password + click-entered PIN + TOTP. A password keylogger
  alone is useless without the mouse-clicked PIN and your authenticator.
- **Keylog-resistant PIN pad.** The on-screen keypad reshuffles after every digit, so
  the PIN is never on the physical keyboard - defeating software and hardware keyloggers.
- **Strong, standard crypto.** AES-256-GCM authenticated encryption, scrypt key
  derivation, a random data key wrapped by your password - all via the vetted
  `cryptography` library, no home-rolled primitives. Filenames are encrypted too.
- **No recovery, no backdoor - and that is the point.** No OS keychain, DPAPI, TPM,
  registry, or CA certificate store holds any secret. Move the `.dat` to any OS and it
  behaves identically.
- **Open source, reproducible.** Run straight from Python source, or build the identical
  `.exe` yourself with PyInstaller and verify it against the signed release.
- **Reversible hardening.** Every hardening script has a revert, a status mode, and (where
  relevant) a "dead-man" auto-revert so a remote lockout can't strand you.

---

## Feature list

### Vault & password manager

| Feature | What it does |
|---|---|
| Encrypted file vault | One `SecureVault.dat` container; AES-256-GCM per blob, encrypted file index (names hidden). |
| Three-factor unlock | Master password + randomized on-screen PIN pad + TOTP code, all checked before the data key is exposed. |
| Explorer-style GUI | Folder tree + file list, search, add/extract/delete, in-memory preview, integrity verify, change password/PIN. |
| Open files in place | Decrypts to a private per-session scratch dir, launches the associated app, offers to save edits back, then overwrites and deletes the plaintext. |
| Password manager | Add/edit/delete logins, strong password generator (CSPRNG), reuse/weak/stale/no-2FA audit, password history, domain-aware search, phishing gate on copy. |
| TOTP (2FA) | RFC 6238 codes generated locally; per-entry TOTP secret; accepts raw base32 or `otpauth://` URIs. |
| Chrome CSV import | Imports a Chrome/Edge/Brave password CSV, skips duplicates, then securely shreds the file. |
| Browser autofill (optional) | MV3 extension <-> native host <-> the running unlocked vault, over a local named pipe. Per-browser pairing with an app-shown PIN and per-request ECDSA P-256 signatures; revocable. |
| Portable secret bundle | Small `.svb` file (separate from the vault) to move TOTP seeds / recovery phrases between devices. |
| Explorer right-click menu | "Send to SV", "Send folder to SV", "Open Secure Vault" - registered per-user (HKCU), no admin. |
| CLIs & self-tests | `SecureVault.exe`/`sv_app.py` CLI, `pw` password CLI, and a suite of self-tests. |
| Aura light & dark | The QuickOpen design system across every window - vault browser, password manager, PIN pad, setup wizards. Follows the desktop's light/dark live; **View -> Switch theme** (or the header control) pins *System / Dark / Light*, saved with the app's other non-secret preferences. |

### Windows hardening scripts (repo root)

Run from an **elevated PowerShell** (unless noted). Run with **no switches** for a
read-only status view; `-Apply` to change; `-Revert` (or the dedicated `Revert-*` script)
to undo. See [`docs/USAGE.md`](docs/USAGE.md) for details and cautions.

| Script | What it does | How to revert |
|---|---|---|
| `New-RestorePoint.ps1` | Enables System Restore on C:, sizes shadow storage, takes a checkpoint. **Run this first.** | It *is* the revert mechanism (System Restore). |
| `Harden-Laptop.ps1` | Master pass: outbound-only firewall, kills LLMNR/NBT-NS/mDNS, disables SMBv1 and inbound-exposing services, LSASS PPL, WDigest, AutoRun, UAC; checks BitLocker. | `Revert-NetworkHardening.ps1` (network parts). |
| `Fix-Gaps.ps1` | Disables stale/Guest/built-in-admin accounts, sets password policy, BitLocker pre-boot PIN policy + recovery-key export, removes Java, DoH template table. | `Revert-FixGaps.ps1` (`-RepairDns`/`-BitLocker`/`-Accounts`/`-All`). Java removal is **not** reversible. |
| `Set-EncryptedDns.ps1` | Points the adapter at DoH-capable public resolvers (1.1.1.1 / 8.8.8.8), self-verifying. | Built-in `-Revert` (back to DHCP); optional dead-man. |
| `Set-PrivateDoh.ps1` | Points the adapter at **your own** DoH endpoints only, plus a watchdog that swaps to public resolvers if yours go dark. | Built-in `-Revert` / `-ToDhcp`; dead-man switch. |
| `Block-AllInbound.ps1` | Sets `AllowInboundRules=False` on all firewall profiles (blocks every inbound, even allowed apps). | Built-in `-Revert` (restores saved state); dead-man switch. |
| `Block-HpSmartInternet.ps1` | Outbound firewall rules so HP Smart reaches only the LAN, not the internet. | Built-in `-Revert` (deletes the rule group). |
| `Reduce-IdleFootprint.ps1` | Stops idle background apps (Edge background/boost, Copilot/Widgets/Search auto-launch). | Built-in `-Revert` (restores saved values). |
| `Remove-StoreBloat.ps1` | Removes + deprovisions unused Store (MSIX) apps. | Built-in `-Revert` (best-effort re-register; some need manual Store reinstall). |
| `Disable-DeviceAssociation.ps1` | Disables DeviceAssociationService so dasHost stops holding UDP 3702 (after reboot). | Built-in `-Revert` (back to Automatic + start). |
| `Set-HpDoctorManual.ps1` | Sets HP Print/Scan Doctor service to Manual and stops it. | Built-in `-Revert` (back to Automatic + start). |
| `Set-OpenWifiManual.ps1` | Sets saved **open** Wi-Fi profiles to manual connect (stops silent auto-join / evil-twin). | Built-in `-Revert` (back to auto). |
| `Harden-Chrome.ps1` | Chrome enterprise-policy hardening (Safe Browsing, HTTPS-only, TLS floor, telemetry off, extension blocklist, updater). | Built-in `-Revert` (deletes the policy keys). `-RemoveTrustWallet` is separate and **irreversible**. |
| `New-IosDohProfile.ps1` | Builds an iOS `.mobileconfig` to point an iPhone at your DoH resolver system-wide. Runs **unelevated**. | Remove the profile on the iPhone (Settings > VPN, DNS & Device Management). |
| `Backup-SecureVault.ps1` | Registers an hourly scheduled task that copies your vault folder to up to three destinations (chained robocopy, never deletes). | Built-in `-Revert` (removes the task; leaves backups). |
| `Install-BrowserFill.ps1` | Registers the autofill extension + native host in Chrome/Edge and allowlists it past the Harden-Chrome blocklist. | Built-in `-Revert` (removes registration + allowlist). |
| `Check-Status.ps1` | Read-only post-reboot health check of all the above. Changes nothing. | N/A (read-only). |

**Irreversible actions to note:** `Fix-Gaps.ps1`'s Java uninstall, and `Harden-Chrome.ps1 -RemoveTrustWallet`.

---

## Requirements

- **Windows 10 or 11** (the hardening scripts and Explorer/registry integration are
  Windows-only; the crypto core is cross-platform).
- **Windows PowerShell 5.1+** for the hardening scripts. Most require an **elevated**
  (Administrator) session; each script's header says so.
- **From source:** **Python 3.8+** (developed and tested on **Python 3.13**), plus the
  `cryptography` package. The signed `.exe` bundles its own runtime - no Python needed.
- **Browser autofill (optional):** **Chrome or Edge 116+** (Manifest V3).

---

## Install

### A. One-click installer (recommended)

Download **`SecureVault-Setup.exe`** from the
[QuickOpen page](https://quickopen.ai/projects/securevault) or the
[GitHub release](https://github.com/quickpod/securevault/releases/latest) and
**double-click it**. No Python, no command line. The installer:

- creates a **Desktop shortcut** and a **Start Menu** entry,
- adds an **Add/Remove Programs** entry (clean uninstall),
- optionally **trusts the QuickOpen Root CA** (a checkbox) so Windows verifies
  our signature natively,
- registers the Explorer right-click menu.

The installer is **Authenticode-signed** by the QuickOpen Code Signing CA. Once
you've trusted our root, Windows shows the publisher as **QuickOpen**. (Because
we run our own certificate authority rather than a commercial one, SmartScreen
may still show a caution on first download — that's expected; the signature and
publisher are verifiable against [`/trust`](https://quickopen.ai/trust).)

Prefer to verify by hand first? Every release also ships a detached signature:

```powershell
openssl cms -verify -binary -inform DER -in SecureVault-Setup.exe.sig `
  -content SecureVault-Setup.exe -CAfile quickopen-root.crt -purpose any -out NUL
```

### B. Manual / from source

```powershell
git clone <this-repo> SecureVault
cd SecureVault
py -m pip install cryptography
py src\sv_app.py           # launches the GUI
```

To also enable browser autofill and the Explorer menu from source, see
[`docs/USAGE.md`](docs/USAGE.md#browser-autofill-setup).

---

## Uninstall

Run the repo's uninstaller from PowerShell:

```powershell
.\uninstall.ps1
```

It **reverts hardening changes it can** (calls each `Revert-*` / `-Revert`), removes the
Explorer shell-integration registry keys, removes the Chrome/Edge native-messaging host
registration (`HKCU\Software\Google\Chrome\NativeMessagingHosts\com.securevault.autofill`
and the Edge equivalent), and deletes the install dir under `%LOCALAPPDATA%\SecureVault`.
It is **idempotent** and prints every action. It never touches your `SecureVault.dat` -
back that up or move it first if you want to keep your data. You must also remove the
unpacked extension from `chrome://extensions` by hand. Full details in
[`docs/USAGE.md`](docs/USAGE.md#uninstall).

---

## Quickstart usage

1. **Create the vault.** Launch `SecureVault.exe` (or `py src\sv_app.py`). With no vault
   yet it offers to create one: set your **password** and **PIN**, and it shows a **TOTP
   enrollment secret / QR once** - add it to your authenticator app immediately. There is
   **no recovery and no backdoor**; write your password + PIN down somewhere safe offline.
2. **Unlock.** Type the password, click the 6-digit PIN on the randomized keypad, enter
   the current TOTP code.
3. **Store things.** Drag files in, or right-click any file in Explorer -> **Send to SV**.
   Open the **Passwords** window to add logins and TOTP secrets.
4. **Open a file in place.** Double-click it; it opens in its normal app and is wiped when
   you close it (you're asked whether to save edits back).
5. **Harden Windows (optional).** Run `New-RestorePoint.ps1` first, then apply the
   hardening scripts you want from an elevated PowerShell. Each has `-Revert`.

**Full, step-by-step usage** - creating/unlocking a vault, the password manager, browser
autofill pairing, TOTP enrollment, opening files, and running each hardening script - is
in **[`docs/USAGE.md`](docs/USAGE.md)**.

---

## Build it yourself

You do **not** have to trust the signed binary. You can run entirely from Python source
(`py src\sv_app.py`) or build the identical `.exe` yourself with PyInstaller. A concrete
command and the reproducibility notes are in **[`docs/BUILD.md`](docs/BUILD.md)**.

---

## Security notes & limitations

SecureVault is honest about what it can and cannot do:

- **Unlocked-state exposure.** While the vault is open and you view/extract a file, that
  plaintext is in memory (and on disk if extracted). At-rest data is the strong,
  unconditional guarantee; nothing userspace can hide plaintext from kernel-level malware
  at the moment you decrypt it.
- **Open-in-place writes plaintext to disk, by design** - the one feature that does. Use
  the memory-only **Preview** if you just want to look.
- **Wiping is best-effort, not erasure.** The scratch copy is overwritten before deletion,
  but on an SSD wear-levelling may leave original blocks readable. Full-disk encryption
  (BitLocker with a pre-boot PIN) is what actually protects remnants.
- **The app you open a file with is a normal program.** It can be online and can leave its
  own copies (Office temp files, recent-docs entries, thumbnails). SecureVault wipes *its*
  scratch copy, not copies another app makes.
- **Keylogger scan is heuristic.** It matches known-tool signatures and cannot detect a
  novel or kernel/hardware logger. The click-only PIN pad is the real defense, not the scan.
- **Autofill is not a hard boundary against same-user malware.** Windows offers no
  process-identity ACL. The mitigations are: the app must be unlocked, per-origin binding,
  single-use signed challenges, and visible, revocable pairings - the same bar as
  mainstream password managers.
- **The portable `.svb` bundle has no PIN/TOTP** - its only protection is its passphrase.
- **No password/PIN recovery.** Lose them and the data is gone. That is deliberate.

The hardening scripts change system state; read each script's header, keep a restore
point, and use the revert paths. Two actions are irreversible (Java removal in
`Fix-Gaps.ps1`, and `Harden-Chrome.ps1 -RemoveTrustWallet`).

---

## License

[Apache-2.0](LICENSE). Copyright 2026 QuickOpen.

*This is an AI-built project published on QuickOpen.*
