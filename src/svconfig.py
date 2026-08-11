#!/usr/bin/env python3
r"""
svconfig - a tiny, NON-SECRET settings file for SecureVault.

The only things kept here are file PATHS: the vault the user last opened and a
short recent-vaults list, so the GUI can reopen the same container next launch
and offer quick switches. It lives at:

    %LOCALAPPDATA%\SecureVault\config.json      (Windows)
    ~/.securevault/config.json                  (fallback / other OS)

NOTHING SECRET IS EVER WRITTEN HERE - no passwords, PINs, TOTP secrets or keys.
The vault itself (SecureVault.dat) stays wherever the user put it; this file only
remembers where that is. Every function degrades quietly (missing/corrupt file
-> empty defaults) so a bad config can never block launching the app.
"""

import os, json

APP_DIRNAME = "SecureVault"
CONFIG_NAME = "config.json"
MAX_RECENT = 8


def config_dir():
    """Per-user config directory (created on demand by save())."""
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return os.path.join(base, APP_DIRNAME)
    return os.path.join(os.path.expanduser("~"), "." + APP_DIRNAME.lower())


def config_path():
    return os.path.join(config_dir(), CONFIG_NAME)


def load():
    """Return the settings dict, or a fresh default dict on any problem."""
    try:
        with open(config_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return _default()
        data.setdefault("last_vault", None)
        rec = data.get("recent")
        data["recent"] = [str(p) for p in rec] if isinstance(rec, list) else []
        return data
    except Exception:
        return _default()


def _default():
    return {"last_vault": None, "recent": []}


def save(cfg):
    """Persist the settings dict. Best-effort: never raises to the caller."""
    try:
        d = config_dir()
        os.makedirs(d, exist_ok=True)
        tmp = config_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"last_vault": cfg.get("last_vault"),
                       "recent": list(cfg.get("recent", []))[:MAX_RECENT]},
                      f, indent=2)
        os.replace(tmp, config_path())
        return True
    except Exception:
        return False


def last_vault():
    """The path of the vault opened most recently, or None."""
    return load().get("last_vault")


def recent_vaults():
    """Recently used vault paths, most-recent first (may include stale paths)."""
    return list(load().get("recent", []))


def remember_vault(path):
    """Record `path` as the current/last vault and push it to the front of the
    recent list (de-duplicated, capped). PATHS ONLY - never a secret."""
    if not path:
        return
    path = os.path.abspath(path)
    cfg = load()
    cfg["last_vault"] = path
    recent = [p for p in cfg.get("recent", []) if os.path.abspath(p) != path]
    recent.insert(0, path)
    cfg["recent"] = recent[:MAX_RECENT]
    save(cfg)


def forget_vault(path):
    """Drop a path from the recent list (e.g. after it is deleted/moved)."""
    if not path:
        return
    path = os.path.abspath(path)
    cfg = load()
    cfg["recent"] = [p for p in cfg.get("recent", []) if os.path.abspath(p) != path]
    if cfg.get("last_vault") and os.path.abspath(cfg["last_vault"]) == path:
        cfg["last_vault"] = cfg["recent"][0] if cfg["recent"] else None
    save(cfg)


if __name__ == "__main__":
    import sys
    print(json.dumps(load(), indent=2))
    print("config file:", config_path(), file=sys.stderr)
