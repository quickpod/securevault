#!/usr/bin/env python3
r"""
svconfig - a tiny, NON-SECRET settings file for SecureVault.

The only things kept here are file PATHS: the vault the user last opened and a
short recent-vaults list, so the GUI can reopen the same container next launch
and offer quick switches. It lives at:

    %LOCALAPPDATA%\SecureVault\config.json      (Windows)
    $XDG_CONFIG_HOME/securevault/config.json    (Linux; ~/.config/securevault)
    ~/.securevault/config.json                  (legacy Linux location - still
                                                 READ if the XDG file does not
                                                 exist yet; writes go to XDG)

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
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return os.path.join(base, APP_DIRNAME)
        return os.path.join(os.path.expanduser("~"), "." + APP_DIRNAME.lower())
    xdg = os.environ.get("XDG_CONFIG_HOME") or \
        os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(xdg, APP_DIRNAME.lower())


def _legacy_config_path():
    """Pre-XDG Linux location (~/.securevault/config.json). Read-only fallback
    so an upgrade keeps the remembered vault; never written to again."""
    return os.path.join(os.path.expanduser("~"), "." + APP_DIRNAME.lower(),
                        CONFIG_NAME)


def config_path():
    return os.path.join(config_dir(), CONFIG_NAME)


def load():
    """Return the settings dict, or a fresh default dict on any problem."""
    try:
        path = config_path()
        if not os.path.isfile(path) and os.name != "nt" \
                and os.path.isfile(_legacy_config_path()):
            path = _legacy_config_path()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return _default()
        data.setdefault("last_vault", None)
        data.setdefault("theme", "system")
        data.setdefault("on_close", "ask")
        data.setdefault("autolock_minutes", DEFAULT_AUTOLOCK_MIN)
        rec = data.get("recent")
        data["recent"] = [str(p) for p in rec] if isinstance(rec, list) else []
        return data
    except Exception:
        return _default()


# Background mode must never become an indefinite unlocked state: the trayed
# app auto-locks after this many idle minutes (no window, no autofill
# activity). Clamped, never zero/"off".
DEFAULT_AUTOLOCK_MIN = 15
AUTOLOCK_MIN, AUTOLOCK_MAX = 1, 240


def _default():
    return {"last_vault": None, "recent": [], "theme": "system",
            "on_close": "ask", "autolock_minutes": DEFAULT_AUTOLOCK_MIN}


def save(cfg):
    """Persist the settings dict. Best-effort: never raises to the caller."""
    try:
        d = config_dir()
        os.makedirs(d, exist_ok=True)
        tmp = config_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"last_vault": cfg.get("last_vault"),
                       "recent": list(cfg.get("recent", []))[:MAX_RECENT],
                       "theme": cfg.get("theme", "system"),
                       "on_close": cfg.get("on_close", "ask"),
                       "autolock_minutes": autolock_minutes(cfg)},
                      f, indent=2)
        os.replace(tmp, config_path())
        return True
    except Exception:
        return False


def on_close():
    """What closing the window with an unlocked vault does:
    "ask" (default) | "tray" (background) | "exit"."""
    v = load().get("on_close", "ask")
    return v if v in ("ask", "tray", "exit") else "ask"


def set_on_close(value):
    if value not in ("ask", "tray", "exit"):
        return
    cfg = load()
    cfg["on_close"] = value
    save(cfg)


def autolock_minutes(cfg=None):
    """Idle minutes before a BACKGROUND (trayed) vault locks itself. Always a
    sane positive number - there is deliberately no 'never'."""
    try:
        v = int((cfg or load()).get("autolock_minutes", DEFAULT_AUTOLOCK_MIN))
    except (TypeError, ValueError):
        v = DEFAULT_AUTOLOCK_MIN
    return max(AUTOLOCK_MIN, min(AUTOLOCK_MAX, v))


def set_autolock_minutes(value):
    cfg = load()
    try:
        cfg["autolock_minutes"] = int(value)
    except (TypeError, ValueError):
        return
    save(cfg)


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


def theme():
    """Appearance preference: "system" (follow the desktop), "dark", "light".

    A preference, not a secret - it belongs in the same paths-only file rather
    than anywhere near the vault.
    """
    return load().get("theme", "system")


def set_theme(value):
    if value not in ("system", "dark", "light"):
        return
    cfg = load()
    cfg["theme"] = value
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
