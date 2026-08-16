#!/usr/bin/env python3
r"""
SecureVault - file-manager shell integration, self-installed by the app.

    SecureVault register     add the right-click menu for this user
    SecureVault unregister   remove it
    SecureVault shellstatus  report whether it is installed, and for what

Windows: verbs under HKCU\Software\Classes (Explorer right-click menu). No
admin rights, nothing left behind for other users. The keys hold only this
program's path - no vault data, no password material, nothing secret.

Linux: a KDE/Dolphin service menu in ~/.local/share/kio/servicemenus (Quick OS
ships Plasma; stock Kubuntu/Neon behave identically). Same contract: per-user,
paths only, written only when asked. The .desktop file must be EXECUTABLE -
KIO Frameworks >= 5.85 ignores non-executable service menus as a security
measure, and a menu that silently never appears is the symptom.

Re-running `register` is how you move to a new machine or a new folder: it
rewrites the entry to point at wherever the program is now.
"""
import os, sys

try:
    import winreg
except ImportError:                       # non-Windows
    winreg = None

IS_WINDOWS = os.name == "nt"

# What the surrounding UI should call the thing - "Explorer menu" means nothing
# on a Linux desktop and "Dolphin" nothing on Windows.
MENU_NAME = "Explorer right-click menu" if IS_WINDOWS else "file manager menu"

CLASSES = r"Software\Classes"

# key under HKCU\Software\Classes, menu label, argument template
VERBS = [
    (r"*\shell\SecureVaultAdd",                 "Send to SV (Secure Vault)",        'add "%1"'),
    (r"Directory\shell\SecureVaultAdd",         "Send folder to SV (Secure Vault)", 'add "%1"'),
    (r"Directory\Background\shell\SecureVault",  "Open Secure Vault",               ""),
]


class ShellError(Exception):
    pass


def target_path():
    r"""The program a user would say they are running: the frozen exe, or the
    sv_app.py entry point in a source checkout. Used for the menu icon and for
    anything shown to a human."""
    if getattr(sys, "frozen", False):
        return os.path.abspath(sys.executable)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "sv_app.py")


def _launcher():
    r"""The program part of the command line, already quoted. Frozen that is
    just the exe; from source it has to be `python(.exe) "sv_app.py"` so that a
    dev checkout registers something that actually runs. On Linux the deb's
    /usr/bin wrapper is preferred when this copy IS the installed one, because
    the wrapper also sets up PYTHONPATH and the window class."""
    if getattr(sys, "frozen", False):
        return f'"{os.path.abspath(sys.executable)}"'
    if not IS_WINDOWS:
        here = os.path.dirname(os.path.abspath(__file__))
        wrapper = "/usr/bin/quickopen-securevault"
        if here.startswith("/opt/quickopen/securevault") and os.access(wrapper, os.X_OK):
            return wrapper
    return f'"{sys.executable}" "{target_path()}"'


def _command(args):
    """Exactly what goes in the verb's command key - one definition, used both
    to write the keys and to decide whether the installed ones are current."""
    return (_launcher() + " " + args).strip()


# --------------------------------------------------------------------- linux
def _servicemenu_path():
    data = os.environ.get("XDG_DATA_HOME") or \
        os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(data, "kio", "servicemenus", "securevault.desktop")


def _servicemenu_body():
    # %F: all selected files/dirs in one invocation -> one unlock, one batch.
    launcher = _launcher().replace('"', "")
    return (
        "[Desktop Entry]\n"
        "Type=Service\n"
        "X-KDE-ServiceTypes=KonqPopupMenu/Plugin\n"
        "MimeType=all/all;\n"
        "Actions=securevaultAdd;securevaultOpen;\n"
        "X-KDE-Priority=TopLevel\n"
        "\n"
        "[Desktop Action securevaultAdd]\n"
        "Name=Send to SV (Secure Vault)\n"
        "Icon=quickopen-securevault\n"
        f"Exec={launcher} add %F\n"
        "\n"
        "[Desktop Action securevaultOpen]\n"
        "Name=Open Secure Vault\n"
        "Icon=quickopen-securevault\n"
        f"Exec={launcher}\n")


def _require_supported():
    if IS_WINDOWS:
        if winreg is None:
            raise ShellError("winreg unavailable")
    # Linux always "supported": writing the KDE service menu is harmless on a
    # non-KDE desktop (it is simply never read).


def is_registered():
    """(installed, command_string_or_None) for the file verb."""
    if IS_WINDOWS:
        if winreg is None:
            return False, None
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                CLASSES + "\\" + VERBS[0][0] + r"\command") as k:
                cmd, _ = winreg.QueryValueEx(k, "")
        except OSError:
            return False, None
        return True, cmd
    p = _servicemenu_path()
    if not os.path.isfile(p):
        return False, None
    try:
        with open(p, encoding="utf-8") as f:
            for line in f:
                if line.startswith("Exec=") and " add " in line:
                    return True, line.strip()[len("Exec="):]
    except OSError:
        return False, None
    return True, None


def is_current():
    """True if the installed menu points at THIS copy of the program. False
    after the program is moved, rebuilt elsewhere, or the profile is reset."""
    installed, cmd = is_registered()
    if not installed:
        return False
    if IS_WINDOWS:
        return cmd == _command(VERBS[0][2])
    return cmd == (_launcher().replace('"', "") + " add %F")


def register():
    """Create (or repoint) the menu. Returns the program now wired up."""
    _require_supported()
    target = target_path()
    if not os.path.exists(target):
        raise ShellError(f"cannot register: {target} does not exist")
    if IS_WINDOWS:
        icon = f'"{os.path.abspath(sys.executable) if getattr(sys, "frozen", False) else target}",0'
        for subkey, label, args in VERBS:
            base = CLASSES + "\\" + subkey
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base) as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, label)
                winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, icon)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r"\command") as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, _command(args))
        _notify_shell()
        return target
    p = _servicemenu_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(_servicemenu_body())
    os.chmod(p, 0o755)                     # KIO >= 5.85 requires the exec bit
    return target


def unregister():
    """Remove the menu. Missing entries are not an error."""
    _require_supported()
    if IS_WINDOWS:
        removed = 0
        for subkey, _label, _args in VERBS:
            base = CLASSES + "\\" + subkey
            for path in (base + r"\command", base):     # leaf first; DeleteKey needs it empty
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
                    removed += 1
                except OSError:
                    pass
        _notify_shell()
        return removed
    try:
        os.remove(_servicemenu_path())
        return 1
    except OSError:
        return 0


def _notify_shell():
    """Tell Explorer the association data changed so the new menu appears
    without a sign-out. Cosmetic - the keys are already live."""
    if os.name != "nt":
        return
    try:
        import ctypes
        SHCNE_ASSOCCHANGED, SHCNF_IDLIST = 0x08000000, 0x0000
        ctypes.windll.shell32.SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None)
    except Exception:
        pass


def status_text():
    installed, cmd = is_registered()
    if not installed:
        return (f"{MENU_NAME.capitalize()}: NOT installed.\n\n"
                "Run 'securevault register' (or Tools > Install) to add it.")
    if not is_current():
        return (f"{MENU_NAME.capitalize()}: installed, but it points somewhere else:\n\n"
                f"  installed : {cmd}\n"
                f"  this copy : {_command(VERBS[0][2]) if IS_WINDOWS else _launcher()}\n\n"
                "Run 'securevault register' to repoint it here.")
    return f"{MENU_NAME.capitalize()}: installed and current.\n\n  {cmd}"
