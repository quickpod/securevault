#!/usr/bin/env python3
r"""
SecureVault unified entry point (this is what gets built into SecureVault.exe).

  SecureVault.exe                 -> launch the Explorer-style GUI
  SecureVault.exe add   <paths>   -> shell "Send to SV": encrypt in, DELETE originals
  SecureVault.exe addkeep <paths> -> encrypt in, keep originals
  SecureVault.exe init|list|get|extract|remove|verify|passwd   -> CLI

Fully self-contained: no network, no OS keychain/registry/DPAPI, no OS or CA
certificate store. The only secret is the password you type.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# The autofill pipe uses multiprocessing.connection. We never spawn a child
# process, but freeze_support() is the standard guard so a PyInstaller one-file
# build can never re-launch itself as a phantom worker. Must run before argparse
# and before importing anything that might touch multiprocessing.
import multiprocessing
multiprocessing.freeze_support()

import securevault as sv


def main():
    argv = sys.argv[1:]
    if argv:                       # any argument => CLI / shell action
        return sv.main(argv)
    import svgui                   # no arguments => GUI browser
    svgui.main()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except sv.VaultError as e:
        sv.gui_info(f"SecureVault: {e}")     # clean dialog instead of a traceback
        sys.exit(4)
    except SystemExit:
        raise
    except Exception as e:
        sv.gui_info(f"SecureVault error: {e}")
        sys.exit(5)
