"""
AegisVault Windows Context Menu & Environment Setup Module
Integrates 'AegisVault ile Kilitle ve İmha Et' into the Windows Explorer Right-Click Context Menu.
Configured via HKCU (HKEY_CURRENT_USER) so no administrator elevation is required!
"""

import os
import sys
import winreg
import argparse
import subprocess
from typing import Optional


def get_python_executable() -> str:
    """Returns pythonw.exe or python.exe suitable for running background scripts."""
    py_dir = os.path.dirname(sys.executable)
    pyw = os.path.join(py_dir, "pythonw.exe")
    if os.path.exists(pyw):
        return pyw
    return sys.executable


def install_context_menu():
    """
    Installs right-click context menu handler for files and directories:
    'AegisVault ile Kilitle ve İmha Et'
    """
    python_exe = get_python_executable()
    main_script = os.path.abspath(os.path.join(os.path.dirname(__file__), "main.py"))

    command_str = f'"{python_exe}" "{main_script}" --lock-direct "%1"'
    menu_title = "AegisVault ile Kilitle ve İmha Et 🛡️"

    targets = [
        r"Software\Classes\*\shell\AegisVaultLock",
        r"Software\Classes\Directory\shell\AegisVaultLock"
    ]

    try:
        for reg_path in targets:
            # Create shell key
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, menu_title)
                # Set icon to shell32 shield icon
                winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, "shell32.dll,48")

            # Create command subkey
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path + r"\command") as cmd_key:
                winreg.SetValueEx(cmd_key, "", 0, winreg.REG_SZ, command_str)

        print("[AegisVault] Windows Sağ Tık Menüsü Entegrasyonu Başarıyla Kuruldu!")
        print("Artık Windows Gezgini'nde herhangi bir dosyaya veya klasöre sağ tıklayarak")
        print("'AegisVault ile Kilitle ve İmha Et' seçeneğini kullanabilirsiniz.")
        return True
    except Exception as e:
        print(f"[AegisVault] Sağ tık menüsü kurulum hatası: {str(e)}")
        return False


def uninstall_context_menu():
    """Removes right-click context menu keys from Windows Registry."""
    targets = [
        r"Software\Classes\*\shell\AegisVaultLock",
        r"Software\Classes\Directory\shell\AegisVaultLock"
    ]

    for reg_path in targets:
        try:
            # Delete subkey first
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, reg_path + r"\command")
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"Hata: {e}")

        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, reg_path)
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"Hata: {e}")

    print("[AegisVault] Windows Sağ Tık Menüsü Kaldırıldı.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AegisVault Windows Setup & Registry Manager")
    parser.add_argument("--install", action="store_true", help="Sağ tık menüsünü yükle")
    parser.add_argument("--uninstall", action="store_true", help="Sağ tık menüsünü kaldır")

    args = parser.parse_args()

    if args.uninstall:
        uninstall_context_menu()
    else:
        install_context_menu()
