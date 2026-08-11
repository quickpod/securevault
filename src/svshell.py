#!/usr/bin/env python3
r"""
SecureVault - Explorer shell integration, self-installed by the exe.

    SecureVault.exe register     add the right-click menu for this user
    SecureVault.exe unregister   remove it
    SecureVault.exe shellstatus  report whether it is installed, and for what

Everything is written under HKCU\Software\Classes, so no admin rights are needed
and nothing is left behind for other users. The keys hold only this program's
path - no vault data, no password material, nothing secret. They are written
only when you ask for it; SecureVault never registers itself silently.

Re-running `register` is how you move to a new machine, a new Windows install,
or a new folder: it rewrites every verb to point at wherever the program is now.
"""
import os, sys

try:
    import winreg
except ImportError:                       # non-Windows: the verbs are no-ops
    winreg = None

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
    just the exe; from source it has to be `python.exe "sv_app.py"` so that a
    dev checkout registers something that actually runs."""
    if getattr(sys, "frozen", False):
        return f'"{os.path.abspath(sys.executable)}"'
    return f'"{sys.executable}" "{target_path()}"'


def _command(args):
    """Exactly what goes in the verb's command key - one definition, used both
    to write the keys and to decide whether the installed ones are current."""
    return (_launcher() + " " + args).strip()


def _require_windows():
    if winreg is None:
        raise ShellError("shell integration is Windows-only")


def is_registered():
    """(installed, command_string_or_None) for the file verb."""
    if winreg is None:
        return False, None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            CLASSES + "\\" + VERBS[0][0] + r"\command") as k:
            cmd, _ = winreg.QueryValueEx(k, "")
    except OSError:
        return False, None
    return True, cmd


def is_current():
    """True if the installed menu points at THIS copy of the program. False
    after the program is moved, rebuilt elsewhere, or the profile is reset."""
    installed, cmd = is_registered()
    return bool(installed and cmd == _command(VERBS[0][2]))


def register():
    """Create (or repoint) every verb. Returns the program now wired up."""
    _require_windows()
    target = target_path()
    if not os.path.exists(target):
        raise ShellError(f"cannot register: {target} does not exist")
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


def unregister():
    """Remove every verb. Missing keys are not an error."""
    _require_windows()
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
        return ("Explorer menu: NOT installed.\n\n"
                "Run 'SecureVault.exe register' (or Tools > Install) to add it.")
    if not is_current():
        return ("Explorer menu: installed, but it points somewhere else:\n\n"
                f"  installed : {cmd}\n"
                f"  this copy : {_command(VERBS[0][2])}\n\n"
                "Run 'SecureVault.exe register' to repoint it here.")
    return f"Explorer menu: installed and current.\n\n  {cmd}"
