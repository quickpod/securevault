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
        "privkey": os.path.join(root, "extension", "_signing_key.pem"),
        "nativehost": os.path.join(root, "nativehost"),
        "hostmanifest": os.path.join(root, "nativehost", HOST_NAME + ".json"),
        "launcher": os.path.join(root, "nativehost", "svhost-launcher.bat"),
        # stable per-user location so a frozen one-file svhost.exe finds it too
        "allowed": os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                                "SecureVault", "svhost_allowed.json"),
        "svhost": os.path.join(root, "src", "svhost.py"),
    }


def _load_or_make_key(privkey_path):
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


def key_and_id(privkey_path):
    key = _load_or_make_key(privkey_path)
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
    manifest_key, ext_id = key_and_id(p["privkey"])
    origin = f"chrome-extension://{ext_id}/"

    # 1. inject the key into the extension manifest
    with open(p["manifest"], "r", encoding="utf-8") as f:
        mani = json.load(f)
    mani["key"] = manifest_key
    with open(p["manifest"], "w", encoding="utf-8") as f:
        json.dump(mani, f, indent=2)

    # 2. native-host launcher: prefer a frozen console svhost.exe, else Python
    launcher = (
        "@echo off\r\n"
        'if exist "%~dp0svhost.exe" (\r\n'
        '  "%~dp0svhost.exe" %*\r\n'
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
