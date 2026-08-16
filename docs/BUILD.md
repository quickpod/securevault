# SecureVault - Build From Source

You never have to trust the signed binary. SecureVault is pure Python (plus one vetted
dependency, `cryptography`), so you can **run it straight from source** or **build the exact
same `.exe` yourself**. Both yield an identical program.

## Requirements

- **Python 3.8+** - developed and tested on **Python 3.13**. (The code uses only f-strings,
  underscore numeric literals and type hints; no walrus/`match`, so older 3.x works, but 3.13
  is what's shipped and tested.)
- The **`cryptography`** package (the only runtime dependency).
- For building the exe: **PyInstaller**.

```powershell
py -m pip install -r requirements.txt pyinstaller   # cryptography + segno (QR)
```

## Run from source (no build)

The single entry point is `src/sv_app.py`. With no arguments it launches the GUI; with any
argument it acts as the CLI.

```powershell
py src\sv_app.py                 # GUI
py src\sv_app.py list            # CLI (same commands as SecureVault.exe)
py src\sv_app.py pw audit
```

Run the self-tests to prove the build on your machine (each exits non-zero on failure):

```powershell
cd src
py selftest.py            # end-to-end vault: crypto, folder tree, open/edit/wipe, shell verbs
py selftest_pw.py         # password manager: store, search, generator, audit, CSV import
py selftest_auth.py       # extension pairing + request-signing rules (refusals)
py selftest_pairing.py    # end-to-end autofill over a real vault
py selftest_bundle.py     # portable .svb bundle format + merge rules
py selftest_ipc.py        # autofill transport: token handshake, fail-closed teardown
py selftest_lock.py       # auto-lock triggers: desktop-lock/suspend mapping, system idle, migration
```

## Build the .exe with PyInstaller

The entry point is `src/sv_app.py`. The GUI, open-in-place, shell-integration, keylogger-scan
and TOTP modules are imported **lazily inside functions**, so they must be forced in as hidden
imports or a build can silently omit them.

```powershell
cd src
pyinstaller --onefile --windowed --name SecureVault ^
  --collect-submodules cryptography ^
  --hidden-import svgui  --hidden-import svopen  --hidden-import svshell ^
  --hidden-import svsec  --hidden-import svtotp  --hidden-import svpass ^
  --hidden-import svpassgui --hidden-import svauth --hidden-import svipc ^
  --hidden-import svchrome  --hidden-import svbundle ^
  --hidden-import svqr --hidden-import svconfig --hidden-import svwizard --hidden-import svautofill_setup ^
  sv_app.py
```

- `--onefile` - a single self-contained `SecureVault.exe`.
- `--windowed` - no console window for the GUI (the CLI paths still print to an attached
  console when run from one).
- `--collect-submodules cryptography` - pull in the native crypto backend fully.
- The `--hidden-import` flags cover the lazily-imported modules.

The result is `src\dist\SecureVault.exe`. Copy it next to your `SecureVault.dat` and run
`SecureVault.exe register` so the Explorer menu points at the new build.

### The native-messaging host (optional, for autofill)

The autofill native host `svhost.py` can be frozen as a small console exe placed next to
`svhost-launcher.bat`; the launcher prefers it and otherwise falls back to Python:

```powershell
pyinstaller --onefile --console --name svhost svhost.py
```

Then re-run `py svautofill_setup.py apply --root %LOCALAPPDATA%\SecureVault` so the launcher
and manifests point at the right place. (See [`USAGE.md`](USAGE.md#browser-autofill-setup).)

## Verifying against the signed release

If a release ships a `SHA256SUMS` file, compare it to your own build:

```powershell
Get-FileHash dist\SecureVault.exe -Algorithm SHA256
```

Note that a **one-file PyInstaller exe is not bit-for-bit reproducible** across machines
(timestamps, absolute paths, PyInstaller/Python patch versions and the bundled `cryptography`
wheel all affect the bytes). So a differing hash does **not** mean the release is bad. The
strong guarantee is at the **source** level: the source you build is the source you can read
here, and running `py src\sv_app.py` uses no compiled binary at all. If you want zero binary
trust, run from source and skip the exe entirely.
