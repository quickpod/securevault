#!/usr/bin/env python3
r"""
SecureVault - a standalone, password-protected encrypted file vault.

Everything lives in ONE container file (default: SecureVault.dat) that you can
bundle next to this program and copy anywhere (e.g. let a cloud-sync or backup
tool copy it offsite).
Without the master password the container is cryptographic noise.

Crypto (all via the vetted `cryptography` library - no home-rolled primitives):
  - master password  --scrypt(N=2^15,r=8,p=1)-->  KEK (key-encrypting key)
  - a random 256-bit DEK (data key) is wrapped by the KEK with AES-256-GCM,
    so you can change the password without re-encrypting the whole vault
  - every stored file: AES-256-GCM, fresh 96-bit nonce, ciphertext+tag
  - the file index (names, sizes, offsets, hashes) is itself AES-256-GCM
    encrypted, so the container leaks neither contents nor filenames

Container layout (single .dat file):
  [ 4 B ] magic  b"SVLT"
  [ 1 B ] format version
  [ 2 B ] header length H (big-endian)
  [ H B ] header JSON (NON-secret KDF params + wrapped DEK + verifier). Every
          field is constant length, so H never changes -> stable data offsets.
  [ ... ] data region: concatenated encrypted file blobs (append-only)
  [ ... ] encrypted index blob (names, sizes, offsets, hashes)
  [ 8 B ] index offset (big-endian, absolute)
  [ 8 B ] index length (big-endian)
  [ 4 B ] footer magic b"SVEN"
The fixed 20-byte footer at EOF points to the index. The data region ends where
the index begins, so no mutable "data_end" is kept in the header.

Usage:
  securevault init                     create the vault + set master password
  securevault add   <path> [...]       encrypt file(s) into the vault, DELETE originals
  securevault addkeep <path> [...]     same, but KEEP originals
  securevault list                     list stored files
  securevault get   <name> [dest]      decrypt one file out of the vault
  securevault extract <destdir>        decrypt everything
  securevault remove <name>            delete a file from the vault
  securevault passwd                   change the master password
  securevault verify                   check every blob's authentication tag
  securevault pw <cmd> [...]           password manager (list/copy/add/gen/import-chrome/audit/...)
  securevault register                 add the Explorer right-click menu (HKCU)
  securevault unregister               remove the Explorer right-click menu
  securevault shellstatus              report whether the menu is installed
Environment:
  SECUREVAULT_DAT   path to the container (default: <exe dir>\SecureVault.dat)
  SECUREVAULT_PW    master password (optional; else prompted, GUI if no console)
"""

import os, sys, json, struct, hashlib, getpass, io, time

# Single-instance marker: the installer's AppMutex checks this to warn the
# user to close the app before install/uninstall. Harmless off Windows.
if os.name == "nt":
    try:
        import ctypes
        ctypes.windll.kernel32.CreateMutexW(None, False, "QuickOpen.SecureVault")
    except Exception:
        pass


def _disable_network():
    """Enforce 'no inbound or outbound connections of any kind'. We import no
    network modules, but this neutralises sockets at runtime so that not even a
    bundled dependency can open, accept, or dial a connection.

    One carve-out, POSIX only: the AF_UNIX family. The Linux autofill bridge
    (svipc) is an AF_UNIX socket in the user's 0700 runtime dir - the exact
    equivalent of the Windows named pipe, which never went through the socket
    module at all. AF_UNIX is filesystem IPC on this machine: it has no route,
    no port and no remote peer, so allowing it does not weaken 'no network'.
    AF_INET/AF_INET6/anything routable stays blocked on both OSes, as do the
    dial-out helpers (create_connection etc.)."""
    import socket
    def _blocked(*a, **k):
        raise OSError("SecureVault: network access is permanently disabled")
    if os.name != "nt" and hasattr(socket, "AF_UNIX"):
        real_socket = socket.socket
        real_socketpair = socket.socketpair
        af_unix = socket.AF_UNIX

        class _UnixOnlySocket(real_socket):
            def __init__(self, family=-1, type=-1, proto=-1, fileno=None):
                # fileno-based construction is how accept() wraps an already-
                # accepted AF_UNIX connection; the family check still applies
                # because accept() passes the listener's family through.
                if family not in (af_unix, -1) or (family == -1 and fileno is None):
                    _blocked()
                super().__init__(family, type, proto, fileno)

        def _unix_socketpair(family=af_unix, *a, **k):
            # On POSIX socketpair() IS an AF_UNIX pair - two connected local
            # fds with no address, no port, no route. GLib's Python bindings
            # need one for their signal-wakeup plumbing, and blocking it
            # killed the tray icon's event loop outright (field defect: the
            # background icon never registered with the StatusNotifierWatcher,
            # stranding the user). Any other family stays blocked.
            if family != af_unix:
                _blocked()
            return real_socketpair(family, *a, **k)

        try:
            socket.socket = _UnixOnlySocket
            socket.socketpair = _unix_socketpair
        except Exception:
            pass
    else:
        # Windows: no AF_UNIX in practice, and CPython emulates socketpair()
        # over AF_INET loopback - so there the full block stays.
        for attr in ("socket", "socketpair"):
            try: setattr(socket, attr, _blocked)
            except Exception: pass
    for attr in ("create_connection", "create_server", "fromfd", "fromshare"):
        if hasattr(socket, attr):
            try: setattr(socket, attr, _blocked)
            except Exception: pass


_disable_network()

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"SVLT"
FOOTER_MAGIC = b"SVEN"
FOOTER_LEN = 8 + 8 + 4          # index_off | index_len | footer magic
VERSION = 1
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
DEK_LEN = 32
NONCE_LEN = 12

# --------------------------------------------------------------------------- kdf
def pw_material(raw: bytes) -> bytes:
    """Reduce the raw password to a fixed 32-byte SHA-256 digest at the input
    boundary. Only this digest is passed inward; the raw password never travels
    beyond the prompt and is never stored. scrypt (below) then stretches it."""
    return hashlib.sha256(raw).digest()

def auth_material(password: bytes, pin: bytes) -> bytes:
    """Two-factor key material: typed PASSWORD + 6-digit PIN (entered on the
    randomized on-screen keypad). Both are required. The combined value is
    SHA-256'd here so neither raw secret travels further in, then scrypt stretches
    it. A password keylogger alone is useless without the click-entered PIN."""
    return hashlib.sha256(password + b"\x1f" + pin).digest()

def derive_kek(material: bytes, salt: bytes) -> bytes:
    # `material` is the SHA-256 of the password, not the raw password
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(material)

def gcm_encrypt(key, plaintext, aad=b""):
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct                      # nonce||ciphertext||tag

def gcm_decrypt(key, blob, aad=b""):
    return AESGCM(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)

# ----------------------------------------------------------------------- vault io
class VaultError(Exception): pass

class Vault:
    def __init__(self, path):
        self.path = path
        self.header = None
        self.dek = None

    # ---- creation / open
    def exists(self):
        return os.path.isfile(self.path)

    def _data_start(self):
        # constant: front header never changes length after create
        return 4 + 1 + 2 + self._hlen

    def create(self, password: bytes):
        if self.exists():
            raise VaultError(f"vault already exists: {self.path}")
        # the default location may not exist yet (e.g. ~/.local/share/securevault
        # on a fresh Linux profile); creating it here keeps every caller honest
        parent = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(parent, exist_ok=True)
        import svtotp
        salt = os.urandom(16)
        kek = derive_kek(password, salt)
        dek = os.urandom(DEK_LEN)
        wrapped = gcm_encrypt(kek, dek, b"dek")
        # verifier lets us reject a wrong password cleanly (not just GCM failure)
        verifier = gcm_encrypt(kek, b"securevault-ok", b"verify")
        # third factor: a TOTP secret, stored WRAPPED by the password+PIN key so
        # the .dat alone never exposes it. Returned so the caller can enroll it.
        # SECUREVAULT_TOTP_SECRET lets you restore/seed a known secret (recovery,
        # scripting); otherwise a fresh random one is generated.
        totp_secret = os.environ.get("SECUREVAULT_TOTP_SECRET") or svtotp.random_secret()
        wrapped_totp = gcm_encrypt(kek, totp_secret.encode("ascii"), b"totp")
        self.dek = dek
        self.totp_secret = totp_secret
        # all fields are fixed length regardless of password -> stable header size
        self.header = {
            "kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
            "salt": salt.hex(), "wrapped_dek": wrapped.hex(), "verifier": verifier.hex(),
            "wrapped_totp": wrapped_totp.hex(),
        }
        hb = self._header_bytes(); self._hlen = len(hb)
        with open(self.path, "wb") as f:
            f.write(MAGIC); f.write(bytes([VERSION]))
            f.write(struct.pack(">H", len(hb))); f.write(hb)
        self._write_index({})            # empty data region + index + footer
        return totp_secret

    def unlock(self, password: bytes, totp_code=None):
        import svtotp
        with open(self.path, "rb") as f:
            if f.read(4) != MAGIC:
                raise VaultError("not a SecureVault container")
            ver = f.read(1)[0]
            if ver != VERSION:
                raise VaultError(f"unsupported version {ver}")
            (hlen,) = struct.unpack(">H", f.read(2))
            self._hlen = hlen
            self.header = json.loads(f.read(hlen))
        salt = bytes.fromhex(self.header["salt"])
        kek = derive_kek(password, salt)
        try:
            gcm_decrypt(kek, bytes.fromhex(self.header["verifier"]), b"verify")
        except Exception:
            raise VaultError("wrong password or PIN")
        # enforce the TOTP factor BEFORE exposing the data key
        if self.header.get("wrapped_totp"):
            secret = gcm_decrypt(kek, bytes.fromhex(self.header["wrapped_totp"]), b"totp").decode("ascii")
            if not svtotp.verify(secret, str(totp_code or "")):
                raise VaultError("wrong or expired authenticator (TOTP) code")
            self.totp_secret = secret
        self.dek = gcm_decrypt(kek, bytes.fromhex(self.header["wrapped_dek"]), b"dek")
        return self

    def _header_bytes(self):
        return json.dumps(self.header).encode("utf-8")

    # ---- footer (fixed 20 bytes at EOF) -> index location
    def _read_footer(self):
        with open(self.path, "rb") as f:
            f.seek(-FOOTER_LEN, os.SEEK_END)
            foot = f.read(FOOTER_LEN)
        if foot[16:20] != FOOTER_MAGIC:
            raise VaultError("corrupt vault: bad footer")
        off, ln = struct.unpack(">QQ", foot[:16])
        return off, ln

    # ---- index (encrypted)
    def _encrypt_index(self, index):
        return gcm_encrypt(self.dek, json.dumps(index).encode("utf-8"), b"index")

    def _read_index(self):
        off, ln = self._read_footer()
        if ln == 0:
            return {}
        with open(self.path, "rb") as f:
            f.seek(off); blob = f.read(ln)
        return json.loads(gcm_decrypt(self.dek, blob, b"index").decode("utf-8"))

    def _write_index(self, index, data_end=None):
        """Write index right after the data region, then the fixed footer.
        data_end = absolute offset where the data region ends (index begins).
        If None, reuse the current index offset (data region unchanged)."""
        if data_end is None:
            try:
                data_end, _ = self._read_footer()
            except Exception:
                data_end = self._data_start()
        blob = self._encrypt_index(index)
        with open(self.path, "r+b" if self.exists() else "wb") as f:
            f.seek(data_end); f.write(blob)
            f.write(struct.pack(">QQ", data_end, len(blob))); f.write(FOOTER_MAGIC)
            f.truncate(data_end + len(blob) + FOOTER_LEN)

    # ---- public operations
    def add(self, src_path, arcname=None, delete_original=True):
        index = self._read_index()
        data_end, _ = self._read_footer()     # data ends where old index began
        with open(src_path, "rb") as f:
            data = f.read()
        name = self._unique(index, arcname or os.path.basename(src_path))
        blob = gcm_encrypt(self.dek, data, name.encode("utf-8"))
        rel_off = data_end - self._data_start()
        with open(self.path, "r+b") as f:
            f.seek(data_end); f.write(blob)   # overwrites old index; we rewrite it below
        index[name] = {
            "off": rel_off, "len": len(blob), "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "src": os.path.abspath(src_path), "mtime": int(os.path.getmtime(src_path)),
        }
        self._write_index(index, data_end=data_end + len(blob))
        if delete_original:
            os.remove(src_path)
        return name

    def _unique(self, index, name):
        if name not in index: return name
        b, e = os.path.splitext(name)
        i = 2
        while f"{b}~{i}{e}" in index: i += 1
        return f"{b}~{i}{e}"

    def list(self):
        return self._read_index()

    def read_bytes(self, name):
        """Decrypt and return one file's bytes (used by the GUI preview)."""
        index = self._read_index()
        if name not in index:
            raise VaultError(f"not in vault: {name}")
        e = index[name]
        with open(self.path, "rb") as f:
            f.seek(self._data_start() + e["off"]); blob = f.read(e["len"])
        data = gcm_decrypt(self.dek, blob, name.encode("utf-8"))
        if hashlib.sha256(data).hexdigest() != e["sha256"]:
            raise VaultError(f"integrity check failed for {name}")
        return data

    def get(self, name, dest):
        data = self.read_bytes(name)
        if os.path.isdir(dest):
            dest = os.path.join(dest, os.path.basename(name))
        os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
        with open(dest, "wb") as f:
            f.write(data)
        return dest

    def write_bytes(self, name, data):
        """Replace an existing entry's contents from bytes in memory (the GUI
        uses this to save back a file you edited after opening it). The new blob
        is APPENDED and the index repointed at it - the superseded blob is left
        in place as dead space rather than rewriting the whole container, which
        on a multi-GB vault would take minutes. `remove` compacts and reclaims
        it. The original `src` is preserved so the listing still shows where the
        file came from."""
        index = self._read_index()
        old = index.get(name)
        data_end, _ = self._read_footer()      # data ends where the index begins
        blob = gcm_encrypt(self.dek, data, name.encode("utf-8"))
        rel_off = data_end - self._data_start()
        with open(self.path, "r+b") as f:
            f.seek(data_end); f.write(blob)    # overwrites the old index, rewritten below
        index[name] = {
            "off": rel_off, "len": len(blob), "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "src": (old or {}).get("src", ""), "mtime": int(time.time()),
        }
        self._write_index(index, data_end=data_end + len(blob))
        return name

    def dead_space(self):
        """Bytes in the data region no longer referenced by the index - what a
        compaction would reclaim. Grows each time a file is saved back."""
        index = self._read_index()
        index_off, _ = self._read_footer()
        live = sum(e["len"] for e in index.values())
        return max(0, index_off - self._data_start() - live)

    def remove(self, name):
        index = self._read_index()
        if name not in index:
            raise VaultError(f"not in vault: {name}")
        del index[name]
        self._compact(index)

    def _compact(self, index):
        """Rewrite the data region to drop unreferenced blobs, then index+footer."""
        ds = self._data_start()
        entries = sorted(index.items(), key=lambda kv: kv[1]["off"])
        new_index = {}
        tmp = self.path + ".tmp"
        with open(self.path, "rb") as src, open(tmp, "wb") as out:
            src.seek(0); out.write(src.read(ds))     # copy header verbatim
            for name, e in entries:
                src.seek(ds + e["off"]); blob = src.read(e["len"])
                e2 = dict(e); e2["off"] = out.tell() - ds
                out.write(blob); new_index[name] = e2
            data_end = out.tell()
            iblob = self._encrypt_index(new_index)
            out.write(iblob)
            out.write(struct.pack(">QQ", data_end, len(iblob))); out.write(FOOTER_MAGIC)
        os.replace(tmp, self.path)

    def verify(self):
        index = self._read_index(); ds = self._data_start(); bad = []
        with open(self.path, "rb") as f:
            for name, e in index.items():
                f.seek(ds + e["off"]); blob = f.read(e["len"])
                try:
                    data = gcm_decrypt(self.dek, blob, name.encode("utf-8"))
                    if hashlib.sha256(data).hexdigest() != e["sha256"]:
                        bad.append((name, "sha mismatch"))
                except Exception as ex:
                    bad.append((name, str(ex)))
        return index, bad

    def change_password(self, new_password: bytes):
        # header fields are all fixed length -> rewrite the header in place
        salt = os.urandom(16)
        kek = derive_kek(new_password, salt)
        self.header["salt"] = salt.hex()
        self.header["wrapped_dek"] = gcm_encrypt(kek, self.dek, b"dek").hex()
        self.header["verifier"] = gcm_encrypt(kek, b"securevault-ok", b"verify").hex()
        if self.header.get("wrapped_totp") and getattr(self, "totp_secret", None):
            self.header["wrapped_totp"] = gcm_encrypt(kek, self.totp_secret.encode("ascii"), b"totp").hex()
        hb = self._header_bytes()
        if len(hb) != self._hlen:
            raise VaultError("internal: header length changed")
        with open(self.path, "r+b") as f:
            f.seek(4 + 1 + 2); f.write(hb)

# ------------------------------------------------------------------ password i/o
def _have_console():
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except Exception:
        return False

def _material_from(pw_str, pin_str):
    """Build the two-factor key material and best-effort wipe the raw secrets."""
    pw = bytearray(pw_str.encode("utf-8"))
    pin = bytearray(pin_str.encode("utf-8"))
    mat = auth_material(bytes(pw), bytes(pin))
    for buf in (pw, pin):
        for i in range(len(buf)):
            buf[i] = 0
    return mat

def prompt_credentials(confirm=False, need_totp=True, title="SecureVault"):
    """Return (key_material, totp_code). Factors: typed PASSWORD + click-entered
    6-digit PIN + authenticator TOTP code (the code is omitted when need_totp is
    False, e.g. while creating a vault before the secret is enrolled).
    - scripting: SECUREVAULT_PW + SECUREVAULT_PIN (+ SECUREVAULT_TOTP) env vars
    - console:   typed inputs
    - GUI:       typed password + randomized numeric keypad + typed TOTP code"""
    if os.environ.get("SECUREVAULT_PW") and os.environ.get("SECUREVAULT_PIN"):
        mat = _material_from(os.environ["SECUREVAULT_PW"], os.environ["SECUREVAULT_PIN"])
        return mat, (os.environ.get("SECUREVAULT_TOTP") if need_totp else None)
    if _have_console():
        while True:
            pw = getpass.getpass(f"{title} password: ")
            pin = getpass.getpass("6-digit PIN: ")
            if not (pw and len(pin) == 6 and pin.isdigit()):
                print("need a password and a 6-digit numeric PIN; try again"); continue
            code = getpass.getpass("authenticator code: ") if need_totp else None
            if not confirm:
                return _material_from(pw, pin), code
            pw2 = getpass.getpass("confirm password: ")
            pin2 = getpass.getpass("confirm PIN: ")
            if pw == pw2 and pin == pin2:
                return _material_from(pw, pin), code
            print("password/PIN mismatch; try again")
    # GUI fallback (Explorer double-click / shell "Send to SV", no console)
    import svgui                     # lazy import avoids a circular import at load
    creds = svgui.gui_prompt_credentials(confirm=confirm, need_totp=need_totp, title=title)
    if creds is None:
        sys.exit(1)
    pw, pin, code = creds
    return _material_from(pw, pin), code

def gui_info(msg, title="SecureVault"):
    if _have_console():
        print(msg); return
    # scripted / automated use: never block on a dialog that needs a click
    if os.environ.get("SECUREVAULT_QUIET") or os.environ.get("SECUREVAULT_PW"):
        return
    import tkinter as tk
    from tkinter import messagebox
    root = tk.Tk(); root.withdraw()
    messagebox.showinfo(title, msg); root.destroy()

# --------------------------------------------------------------------------- cli
def default_dat():
    """LAST-RESORT vault location. Prefer resolve_dat() for the full precedence
    chain; this is only its final fallback. The SECUREVAULT_DAT override is
    still honoured here for callers (and older code paths) that use
    default_dat() directly.

    Windows keeps the historical 'next to the exe/script' default. On Linux the
    program lives in read-only /opt (the deb), so 'next to the script' can
    never hold a vault; the default is the XDG data dir instead
    (~/.local/share/securevault/SecureVault.dat) - unless a dev checkout
    already has a vault next to the source, which keeps working."""
    if os.environ.get("SECUREVAULT_DAT"):
        return os.environ["SECUREVAULT_DAT"]
    base = os.path.dirname(sys.executable if getattr(sys, "frozen", False)
                           else os.path.abspath(__file__))
    legacy = os.path.join(base, "SecureVault.dat")
    if os.name == "nt" or os.path.isfile(legacy):
        return legacy
    data_home = os.environ.get("XDG_DATA_HOME") or \
        os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(data_home, "securevault", "SecureVault.dat")


def resolve_dat(explicit=None, remember=True):
    r"""Work out which container file to use, in precedence order:
      1. `explicit` - a path from `--dat`/`--vault` (CLI) or a GUI chooser.
      2. SECUREVAULT_DAT environment override.
      3. the vault remembered in config.json, IF that file still exists.
      4. default_dat() next to the exe/script (last resort).
    When `remember` is set and we land on an explicit path or an existing file,
    the choice is written back to config.json (paths only, never secrets)."""
    import svconfig
    if explicit:
        dat = os.path.abspath(explicit)
    elif os.environ.get("SECUREVAULT_DAT"):
        dat = os.environ["SECUREVAULT_DAT"]
    else:
        remembered = svconfig.last_vault()
        if remembered and os.path.isfile(remembered):
            dat = remembered
        else:
            dat = default_dat()
    if remember and (explicit or os.path.isfile(dat)):
        try:
            svconfig.remember_vault(dat)
        except Exception:
            pass
    return dat


def remember_vault(path):
    """Thin re-export so GUI/CLI callers can persist a chosen path via `sv`."""
    import svconfig
    try:
        svconfig.remember_vault(path)
    except Exception:
        pass


def _extract_dat(argv):
    """Pull an optional `--dat <path>` / `--vault <path>` (or `--dat=<path>`)
    out of the argument list, wherever it appears. Returns (remaining_argv,
    explicit_path_or_None). Honoured by every command."""
    out, explicit = [], None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--dat", "--vault"):
            if i + 1 < len(argv):
                explicit = argv[i + 1]; i += 2; continue
            i += 1; continue
        if a.startswith("--dat=") or a.startswith("--vault="):
            explicit = a.split("=", 1)[1]; i += 1; continue
        out.append(a); i += 1
    return out, explicit

def _show_enrollment(secret):
    import svtotp
    uri = svtotp.provisioning_uri(secret, account="SecureVault", issuer="SecureVault")
    # Print a scannable QR to the terminal for CLI users (falls back silently).
    try:
        import svqr
        art = svqr.ascii_qr(uri)
        if art:
            print("\nScan this with your authenticator app (shown once):\n")
            print(art)
    except Exception:
        pass
    gui_info("Add this authenticator (TOTP) secret to your app NOW - it is shown "
             "only once. Scan the QR in your terminal, or enter it by hand:\n\n"
             f"  Secret : {secret}\n\n"
             f"  otpauth URI:\n  {uri}\n\n"
             "Google Authenticator / Authy / Aegis / 1Password all work. "
             "You will need a code from it every time you open the vault.")

def open_vault(create_ok=False, dat=None):
    dat = dat or resolve_dat()
    v = Vault(dat)
    if not v.exists():
        if not create_ok:
            gui_info(f"No vault found at:\n{dat}\n\nRun 'securevault init' first.")
            sys.exit(2)
        mat, _ = prompt_credentials(confirm=True, need_totp=False)
        secret = v.create(mat)
        _show_enrollment(secret)
        return v
    mat, code = prompt_credentials(need_totp=True)
    return v.unlock(mat, code)

def main(argv):
    # A global `--dat <path>` / `--vault <path>` may appear anywhere and takes
    # precedence over SECUREVAULT_DAT and the remembered/default location.
    argv, _explicit_dat = _extract_dat(list(argv))
    if not argv:
        print(__doc__); return 0
    cmd, rest = argv[0], argv[1:]
    dat = resolve_dat(_explicit_dat)

    if cmd == "init":
        if os.path.isfile(dat):
            gui_info(f"Vault already exists:\n{dat}"); return 1
        v = Vault(dat)
        mat, _ = prompt_credentials(confirm=True, need_totp=False)
        secret = v.create(mat)
        gui_info(f"Secure Vault created:\n{dat}\nKeep your password + PIN safe - they cannot be recovered.")
        _show_enrollment(secret)
        return 0

    if cmd in ("add", "addkeep"):
        if not rest:
            gui_info("Send to SV: no files given."); return 1
        v = open_vault(dat=dat)
        delete = (cmd == "add")
        done = []
        for p in rest:
            if os.path.isdir(p):
                for dp, dn, fn in os.walk(p):
                    for n in fn:
                        fpath = os.path.join(dp, n)
                        rel = os.path.relpath(fpath, os.path.dirname(p))
                        done.append(v.add(fpath, arcname=rel.replace(os.sep, "/"),
                                          delete_original=delete))
                if delete:
                    try: os.rmdir(p)
                    except OSError: pass
            else:
                done.append(v.add(p, delete_original=delete))
        gui_info(f"Added {len(done)} file(s) to the Secure Vault"
                 + (" and removed the original(s)." if delete else "."))
        return 0

    if cmd == "list":
        v = open_vault(dat=dat); idx = v.list()
        total = sum(e["size"] for e in idx.values())
        print(f"{len(idx)} file(s), {total/1024/1024:.1f} MB decrypted:")
        for name, e in sorted(idx.items()):
            print(f"  {e['size']:>10} B  {name}")
        return 0

    if cmd == "get":
        if not rest:
            print("usage: securevault get <name> [dest]"); return 1
        v = open_vault(dat=dat)
        dest = rest[1] if len(rest) > 1 else os.getcwd()
        out = v.get(rest[0], dest); gui_info(f"Extracted -> {out}"); return 0

    if cmd == "extract":
        v = open_vault(dat=dat)
        destdir = rest[0] if rest else os.getcwd()
        idx = v.list()
        for name in idx:
            v.get(name, os.path.join(destdir, name))
        gui_info(f"Extracted {len(idx)} file(s) -> {destdir}"); return 0

    if cmd == "remove":
        if not rest: print("usage: securevault remove <name>"); return 1
        v = open_vault(dat=dat); v.remove(rest[0]); gui_info(f"Removed {rest[0]}"); return 0

    if cmd == "verify":
        v = open_vault(dat=dat); idx, bad = v.verify()
        if bad:
            gui_info("INTEGRITY FAILURES:\n" + "\n".join(f"{n}: {r}" for n, r in bad)); return 3
        gui_info(f"OK - all {len(idx)} file(s) authenticated."); return 0

    if cmd == "passwd":
        v = open_vault(dat=dat)
        newmat, _ = prompt_credentials(confirm=True, need_totp=False, title="New SecureVault password")
        v.change_password(newmat)
        gui_info("Master password and PIN changed (authenticator secret unchanged)."); return 0

    if cmd == "pw":
        # password manager. Same vault, same three factors - open_vault(dat=dat)
        # enforces password + PIN + TOTP before the store is even loaded.
        import svpass, svpasscli
        v = open_vault(dat=dat)
        store = svpass.PasswordStore(v)
        store.load()
        return svpasscli.run(store, rest)

    if cmd in ("register", "unregister", "shellstatus"):
        # Explorer right-click menu. No vault access, no password, no admin -
        # HKCU only. Re-run `register` after moving the exe or rebuilding the OS.
        import svshell
        try:
            if cmd == "register":
                exe = svshell.register()
                gui_info(f"Explorer menu installed for this user.\n\n"
                         f"Right-click any file -> 'Send to SV (Secure Vault)'\n\nExe: {exe}")
            elif cmd == "unregister":
                svshell.unregister()
                gui_info("Explorer menu removed.")
            else:
                gui_info(svshell.status_text())
        except svshell.ShellError as e:
            gui_info(f"SecureVault: {e}"); return 1
        return 0

    if cmd == "scan":                      # best-effort keylogger/monitoring check
        import svsec
        w = svsec.scan()
        gui_info("No known keyloggers found (heuristic scan only)." if not w
                 else "Possible monitoring detected:\n  - " + "\n  - ".join(w))
        return 0 if not w else 6

    print(__doc__); return 1

if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except VaultError as e:
        gui_info(f"SecureVault error: {e}"); sys.exit(4)
