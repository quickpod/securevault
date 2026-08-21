#!/usr/bin/env python3
r"""
svautofill_setup - generate the stable extension key + ID and write every
config file the browser-autofill bridge needs. Registry and policy are done by
Install-BrowserFill.ps1; this half is pure file generation so it can be tested
without touching the machine.

Chrome/Edge derive an unpacked extension's ID from the public key in its
manifest "key" field: id = base16->a-p of the first 16 bytes of SHA-256 of the
DER SubjectPublicKeyInfo. We generate an RSA key once, keep the private half
(for a future .crx if ever wanted), embed the public half, and compute the ID -
so the same ID is used in the manifest, the native-host allowed_origins, and
the policy allowlist.

  python svautofill_setup.py <apply|status|paths> [--root %LOCALAPPDATA%\SecureVault]
"""

import os, sys, json, base64, hashlib

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

HOST_NAME = "com.securevault.autofill"


def paths(root):
    return {
        "root": root,
        "ext": os.path.join(root, "extension"),
        "manifest": os.path.join(root, "extension", "manifest.json"),
        # NOT inside extension/: Chromium refuses to load an unpacked
        # extension containing any name that starts with "_" (reserved), so a
        # key written there made the extension unloadable the moment the wizard
        # ran. A private key also has no business in a directory that gets
        # loaded, packed into a .crx or zipped up. Keep it beside the other
        # per-user state instead.
        "privkey": os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                                "SecureVault", "signing_key.pem"),
        # Pre-1.0.12 location, still read once so an existing install keeps its
        # extension ID instead of silently minting a new one on upgrade.
        "privkey_legacy": os.path.join(root, "extension", "_signing_key.pem"),
        "nativehost": os.path.join(root, "nativehost"),
        "hostmanifest": os.path.join(root, "nativehost", HOST_NAME + ".json"),
        "launcher": os.path.join(root, "nativehost", "svhost-launcher.bat"),
        # stable per-user location so a frozen one-file svhost.exe finds it too
        "allowed": os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                                "SecureVault", "svhost_allowed.json"),
        "svhost": os.path.join(root, "src", "svhost.py"),
    }


def _load_or_make_key(privkey_path, legacy_path=None):
    os.makedirs(os.path.dirname(privkey_path), exist_ok=True)
    # Migrate a pre-1.0.12 key out of extension/ before deciding to generate:
    # losing it would change the derived extension ID and break every existing
    # browser pairing.
    if legacy_path and os.path.isfile(legacy_path) and not os.path.isfile(privkey_path):
        try:
            os.replace(legacy_path, privkey_path)
        except OSError:
            pass
    if os.path.isfile(privkey_path):
        with open(privkey_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(privkey_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        try:
            user = os.environ.get("USERNAME", "")
            if user:
                os.system(f'icacls "{privkey_path}" /inheritance:r /grant:r "{user}:F" >nul 2>&1')
        except Exception:
            pass
    return key


def key_and_id(privkey_path, legacy_path=None):
    key = _load_or_make_key(privkey_path, legacy_path)
    der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    manifest_key = base64.b64encode(der).decode("ascii")
    digest = hashlib.sha256(der).digest()[:16]
    ext_id = "".join(chr(ord("a") + (b >> 4)) + chr(ord("a") + (b & 0x0F)) for b in digest)
    return manifest_key, ext_id


def set_allowed_origin(root, origin):
    """(Re)write the native-host manifest's allowed_origins AND the host's own
    second-check allow-list so both name exactly `origin`. Single source of
    truth for those two files: apply() uses it, and the setup wizard reuses it
    when the browser assigns a different extension ID than the derived one
    (Chrome only pins our derived ID once the manifest "key" is present)."""
    p = paths(root)
    os.makedirs(p["nativehost"], exist_ok=True)
    # host manifest: keep any existing metadata, replace only allowed_origins
    if os.path.isfile(p["hostmanifest"]):
        with open(p["hostmanifest"], "r", encoding="utf-8") as f:
            host = json.load(f)
    else:
        host = {"name": HOST_NAME, "description": "SecureVault Autofill host",
                "path": p["launcher"], "type": "stdio"}
    # Always (re)assert the launcher path. The installer SHIPS this manifest as
    # a template whose path is a literal "%LOCALAPPDATA%\SecureVault\..."
    # placeholder, so the isfile() branch above always won and the else branch
    # that sets a real path never ran. Chrome does not expand environment
    # variables here, and that placeholder pointed at the config directory
    # rather than the install directory, so the host could never launch.
    host["path"] = p["launcher"]
    host["allowed_origins"] = [origin]
    with open(p["hostmanifest"], "w", encoding="utf-8") as f:
        json.dump(host, f, indent=2)
    # the host's own second-check list of allowed caller origins
    os.makedirs(os.path.dirname(p["allowed"]), exist_ok=True)
    with open(p["allowed"], "w", encoding="utf-8") as f:
        json.dump([{"origin": origin}], f, indent=2)
    return {"hostmanifest": p["hostmanifest"], "allowed": p["allowed"], "origin": origin}


def apply(root):
    p = paths(root)
    os.makedirs(p["nativehost"], exist_ok=True)
    manifest_key, ext_id = key_and_id(p["privkey"], p.get("privkey_legacy"))
    origin = f"chrome-extension://{ext_id}/"

    # 1. inject the key into the extension manifest
    with open(p["manifest"], "r", encoding="utf-8") as f:
        mani = json.load(f)
    mani["key"] = manifest_key
    with open(p["manifest"], "w", encoding="utf-8") as f:
        json.dump(mani, f, indent=2)

    # 2. native-host launcher: prefer a frozen console svhost.exe (checked both
    #    next to this .bat and one level up in the app root, since the installer
    #    ships it in the app root), else fall back to the Python source.
    launcher = (
        "@echo off\r\n"
        'if exist "%~dp0svhost.exe" (\r\n'
        '  "%~dp0svhost.exe" %*\r\n'
        ') else if exist "%~dp0..\\svhost.exe" (\r\n'
        '  "%~dp0..\\svhost.exe" %*\r\n'
        ") else (\r\n"
        f'  "{sys.executable}" "{p["svhost"]}" %*\r\n'
        ")\r\n")
    with open(p["launcher"], "w", encoding="utf-8") as f:
        f.write(launcher)

    # 3 + 4. native-messaging host manifest + the host's own allow-list
    set_allowed_origin(root, origin)

    return {"ext_id": ext_id, "origin": origin, "hostmanifest": p["hostmanifest"],
            "launcher": p["launcher"], "manifest": p["manifest"],
            "python": sys.executable}


def status(root):
    p = paths(root)
    out = {"files": {}}
    for k in ("manifest", "privkey", "hostmanifest", "launcher", "allowed"):
        out["files"][k] = os.path.isfile(p[k])
    if os.path.isfile(p["privkey"]):
        _, ext_id = key_and_id(p["privkey"])
        out["ext_id"] = ext_id
        out["origin"] = f"chrome-extension://{ext_id}/"
    return out


# --------------------------------------------------------------------- linux
# On Linux the extension identity is FIXED at build time: the repo manifest
# carries a pinned "key" (public half of the project signing key held in the
# build CA area), so the ID is the same for the packed .crx Quick Browser
# pre-installs, an external install, and a dev-mode "Load unpacked". The
# system-wide native-messaging host manifests for Quick Browser/Chromium,
# Chrome and Edge ship in the deb (packaging/linux/rootfs/etc/...); the
# functions below cover the per-user case (other Chromium browsers, or a
# non-deb checkout) by writing the same manifest into the browser's user-level
# NativeMessagingHosts dir.

def app_root():
    """The installed/checkout root that holds extension/ and nativehost/."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def shipped_ext_id(root=None):
    """Extension ID derived from the pinned manifest "key" - no private key
    involved (the ID is a hash of the PUBLIC key, same derivation Chromium
    uses). Empty string if the manifest has no key (unconfigured checkout)."""
    root = root or app_root()
    try:
        with open(os.path.join(root, "extension", "manifest.json"),
                  encoding="utf-8") as f:
            key_b64 = json.load(f).get("key", "")
        der = base64.b64decode(key_b64)
        digest = hashlib.sha256(der).digest()[:16]
        return "".join(chr(ord("a") + (b >> 4)) + chr(ord("a") + (b & 0x0F))
                       for b in digest)
    except Exception:
        return ""


# system host-manifest locations the debs install into, and the per-user
# equivalents each browser consults (Chromium keeps user-level manifests under
# its user-data dir; Chrome/Edge under their own dotted dirs)
LINUX_SYSTEM_HOST_DIRS = [
    "/etc/chromium/native-messaging-hosts",          # Quick Browser + Chromium
    "/etc/opt/chrome/native-messaging-hosts",        # Google Chrome
    "/etc/opt/edge/native-messaging-hosts",          # Microsoft Edge
]

def linux_user_host_dirs():
    home = os.path.expanduser("~")
    cfg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    return [
        os.path.join(cfg, "chromium", "NativeMessagingHosts"),
        os.path.join(cfg, "google-chrome", "NativeMessagingHosts"),
        os.path.join(cfg, "microsoft-edge", "NativeMessagingHosts"),
        os.path.join(cfg, "BraveSoftware", "Brave-Browser", "NativeMessagingHosts"),
    ]


def linux_host_manifest(root=None, ext_id=None):
    root = root or app_root()
    ext_id = ext_id or shipped_ext_id(root)
    return {
        "name": HOST_NAME,
        "description": "SecureVault Autofill host",
        "path": os.path.join(root, "nativehost", "svhost"),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{ext_id}/"],
    }


def linux_apply_user(root=None, ext_id=None, dirs=None):
    """Write the per-user host manifests. Returns {written: [...], ext_id}."""
    root = root or app_root()
    ext_id = ext_id or shipped_ext_id(root)
    if not ext_id:
        raise RuntimeError("extension/manifest.json has no pinned key - "
                           "cannot derive the extension ID")
    manifest = linux_host_manifest(root, ext_id)
    written = []
    for d in (dirs if dirs is not None else linux_user_host_dirs()):
        try:
            os.makedirs(d, exist_ok=True)
            p = os.path.join(d, HOST_NAME + ".json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
            written.append(p)
        except OSError:
            pass
    return {"written": written, "ext_id": ext_id,
            "origin": f"chrome-extension://{ext_id}/",
            "extdir": os.path.join(root, "extension")}


def linux_status(root=None):
    root = root or app_root()
    ext_id = shipped_ext_id(root)
    sys_present = [d for d in LINUX_SYSTEM_HOST_DIRS
                   if os.path.isfile(os.path.join(d, HOST_NAME + ".json"))]
    user_present = [os.path.join(d, HOST_NAME + ".json")
                    for d in linux_user_host_dirs()
                    if os.path.isfile(os.path.join(d, HOST_NAME + ".json"))]
    return {"ext_id": ext_id, "extdir": os.path.join(root, "extension"),
            "system_manifests": sys_present, "user_manifests": user_present}


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    root = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "SecureVault")
    if "--root" in sys.argv:
        root = sys.argv[sys.argv.index("--root") + 1]
    if action == "apply":
        print(json.dumps(apply(root), indent=2))
    elif action == "paths":
        print(json.dumps(paths(root), indent=2))
    else:
        print(json.dumps(status(root), indent=2))
