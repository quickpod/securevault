#!/usr/bin/env python3
r"""
svautostart - start SecureVault at login, LOCKED, minimized to the tray.

Why: autofill is only available while SecureVault runs. Starting it at login -
locked, as a tray icon, no window and no prompt shoved at the user - means
autofill is one unlock away instead of "find and launch the app first".
Fail-closed is untouched: a locked autostarted instance has no socket and no
token; unlocking still takes all three factors.

Policy (owner-specified):
  * enabled by DEFAULT the first time a vault is opened/created on a machine
    (never on a machine where no vault has ever been opened);
  * an explicit, toggleable preference (Tools > Preferences);
  * per-user mechanisms only:
      Linux    ~/.config/autostart/quickopen-securevault.desktop
               (TryExec points at the packaged launcher, so after the package
                is uninstalled the entry silently stops firing)
      Windows  HKCU\Software\Microsoft\Windows\CurrentVersion\Run
               (removed by uninstall.ps1)
"""
import os, sys

APP_NAME = "QuickOpen SecureVault"
RUN_VALUE = "QuickOpenSecureVault"                       # HKCU Run value name
DESKTOP_BASENAME = "quickopen-securevault.desktop"

IS_WINDOWS = os.name == "nt"


def _launcher():
    """(argv0, pretty_command). Prefers the installed entry points; falls back
    to `python sv_app.py` for a source checkout."""
    if getattr(sys, "frozen", False):
        exe = os.path.abspath(sys.executable)
        return exe, f'"{exe}"'
    here = os.path.dirname(os.path.abspath(__file__))
    if not IS_WINDOWS:
        wrapper = "/usr/bin/quickopen-securevault"
        if here.startswith("/opt/quickopen/securevault") and os.access(wrapper, os.X_OK):
            return wrapper, wrapper
    entry = os.path.join(here, "sv_app.py")
    return sys.executable, f'"{sys.executable}" "{entry}"'


def _desktop_path():
    cfg = os.environ.get("XDG_CONFIG_HOME") or \
        os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(cfg, "autostart", DESKTOP_BASENAME)


def enable():
    """Install/refresh the login entry (with the --locked flag). Best-effort:
    returns True on success."""
    try:
        if IS_WINDOWS:
            import winreg
            argv0, cmd = _launcher()
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  r"Software\Microsoft\Windows\CurrentVersion\Run") as k:
                winreg.SetValueEx(k, RUN_VALUE, 0, winreg.REG_SZ, f"{cmd} --locked")
            return True
        argv0, cmd = _launcher()
        p = _desktop_path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tryexec = f"TryExec={argv0}\n" if os.path.isabs(argv0) and \
            os.access(argv0, os.X_OK) else ""
        with open(p, "w", encoding="utf-8") as f:
            f.write(
                "[Desktop Entry]\n"
                "Type=Application\n"
                f"Name={APP_NAME}\n"
                "Comment=Starts SecureVault locked in the tray so autofill is "
                "one unlock away\n"
                f"Exec={cmd} --locked\n"
                + tryexec +
                "Icon=quickopen-securevault\n"
                "Terminal=false\n"
                "X-GNOME-Autostart-enabled=true\n"
                # after the panel, so the StatusNotifier host exists when the
                # tray icon registers
                "X-KDE-autostart-after=panel\n")
        return True
    except Exception:
        return False


def disable():
    try:
        if IS_WINDOWS:
            import winreg
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                                    0, winreg.KEY_SET_VALUE) as k:
                    winreg.DeleteValue(k, RUN_VALUE)
            except OSError:
                pass
            return True
        try:
            os.remove(_desktop_path())
        except OSError:
            pass
        return True
    except Exception:
        return False


def is_enabled():
    if IS_WINDOWS:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Run") as k:
                winreg.QueryValueEx(k, RUN_VALUE)
            return True
        except OSError:
            return False
    return os.path.isfile(_desktop_path())


def apply_pref(enabled):
    """Make reality match the preference."""
    return enable() if enabled else disable()


def ensure_default():
    """Called after a successful vault open/create: the FIRST one on this
    machine turns autostart on by default (recorded so a later explicit 'off'
    is never overridden). Refreshes the entry while the pref is on, so a moved
    install repoints itself."""
    import svconfig
    cfg = svconfig.load()
    pref = cfg.get("autostart")
    if pref is None:
        cfg["autostart"] = True
        svconfig.save(cfg)
        pref = True
    if pref:
        enable()
    return pref
