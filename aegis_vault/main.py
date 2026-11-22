"""
AegisVault Main Application Entrypoint
System Tray integration (pystray), CustomTkinter GUI, Background Watcher,
Panic Hotkey Listener, and Direct Context-Menu Handler.
"""

import os
import sys
import argparse
import threading
from typing import Optional

from PIL import Image, ImageDraw
import pystray

from .core.crypto_engine import encrypt_file_stream, load_public_key
from .core.shredder import shred_file, shred_directory
from .services.usb_guard import PanicManager, start_panic_hotkey_listener, USBDetector
from .ui.app_window import AegisVaultApp

APP_NAME = "AegisVault"
APPDATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "AegisVault")
DEFAULT_VAULT_DIR = os.path.join(os.path.expanduser("~"), "Desktop", "AegisVault_DropBox")


def create_tray_icon_image() -> Image.Image:
    """Generates a dynamic high-contrast security shield icon in RAM."""
    img = Image.new("RGBA", (64, 64), color=(0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Outer Shield Shape
    shield_coords = [
        (32, 4),
        (58, 14),
        (58, 38),
        (32, 60),
        (6, 38),
        (6, 14)
    ]
    # Blue/Cyan Gradient fill
    draw.polygon(shield_coords, fill="#0284c7", outline="#38bdf8", width=3)

    # Inner Lock / Cross
    draw.rectangle([24, 28, 40, 44], fill="#f8fafc")
    draw.arc([26, 18, 38, 30], start=180, end=0, fill="#f8fafc", width=3)
    draw.ellipse([30, 33, 34, 37], fill="#0284c7")
    draw.rectangle([31, 36, 33, 40], fill="#0284c7")

    return img


def handle_direct_lock(target_path: str):
    """
    Invoked directly from the Windows Explorer context menu.
    Locks target file/directory with Public Key and forensically shreds original.
    """
    public_key_path = os.path.join(APPDATA_DIR, "keys", "public.pem")
    if not os.path.exists(public_key_path):
        import ctypes
        ctypes.windll.user32.MessageBoxW(
            0,
            "AegisVault Public Key bulunamadı!\nLütfen önce uygulamayı açıp USB Anahtar Kurulumunu tamamlayın.",
            "AegisVault - Hata",
            0x10 | 0x10000
        )
        sys.exit(1)

    try:
        public_key = load_public_key(public_key_path)

        if os.path.isfile(target_path):
            dest_aegis = target_path + ".aegis"
            encrypt_file_stream(target_path, dest_aegis, public_key)
            shred_file(target_path, passes=3)
        elif os.path.isdir(target_path):
            import shutil
            temp_zip = target_path + ".zip"
            shutil.make_archive(target_path, 'zip', target_path)
            dest_aegis = target_path + "_folder.aegis"
            encrypt_file_stream(temp_zip, dest_aegis, public_key)
            shred_file(temp_zip, passes=1)
            shred_directory(target_path, passes=1)

        import ctypes
        ctypes.windll.user32.MessageBoxW(
            0,
            f"Mühürlendi ve Orijinal Açık Dosya Adli Bilişim Seviyesinde Yok Edildi!\n\nKasa Dosyası:\n{dest_aegis}",
            "AegisVault — Güvenli Kilitleme",
            0x40 | 0x10000
        )
    except Exception as e:
        import ctypes
        ctypes.windll.user32.MessageBoxW(
            0,
            f"Kilitleme sırasında hata oluştu:\n{str(e)}",
            "AegisVault — Hata",
            0x10 | 0x10000
        )
        sys.exit(1)


class AegisVaultTrayController:
    """Manages system tray lifecycle and bridges CustomTkinter GUI."""

    def __init__(self):
        os.makedirs(APPDATA_DIR, exist_ok=True)
        os.makedirs(DEFAULT_VAULT_DIR, exist_ok=True)

        self.gui_app: Optional[AegisVaultApp] = None
        self.tray_icon: Optional[pystray.Icon] = None
        self.is_quitting = False

    def build_tray_menu(self) -> pystray.Menu:
        return pystray.Menu(
            pystray.MenuItem("🛡️ AegisVault Panelini Aç", self.show_gui, default=True),
            pystray.MenuItem("🔑 USB Anahtar Kurulumu", lambda: self.show_gui("wizard")),
            pystray.MenuItem("📂 Kasa Klasörünü Aç", lambda: os.startfile(DEFAULT_VAULT_DIR)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("🚨 ACİL PANİK KİLİDİ (Ctrl+Alt+Shift+X)", lambda: PanicManager.trigger_panic("Tray Panik")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("❌ Güvenli Çıkış", self.quit_application)
        )

    def show_gui(self, view_name: Optional[str] = None):
        """Restores and focuses GUI window."""
        if self.gui_app:
            self.gui_app.after(0, self._restore_gui_window, view_name)

    def _restore_gui_window(self, view_name: Optional[str] = None):
        if self.gui_app:
            self.gui_app.deiconify()
            self.gui_app.lift()
            self.gui_app.focus_force()
            if view_name:
                self.gui_app.show_view(view_name)

    def hide_gui(self):
        """Minimizes GUI to tray."""
        if self.gui_app and not self.is_quitting:
            self.gui_app.withdraw()

    def quit_application(self):
        """Gracefully shuts down services and exits."""
        self.is_quitting = True
        PanicManager.trigger_panic("Uygulama Kapatılıyor")
        if self.gui_app:
            if hasattr(self.gui_app, "watcher_service"):
                self.gui_app.watcher_service.stop()
            self.gui_app.after(0, self.gui_app.destroy)
        if self.tray_icon:
            self.tray_icon.stop()
        sys.exit(0)

    def run(self):
        # 1. Start global Panic Hotkey Listener (Ctrl + Alt + Shift + X)
        start_panic_hotkey_listener(lambda reason: PanicManager.trigger_panic(reason))

        # 2. Setup Tray Icon
        icon_img = create_tray_icon_image()
        self.tray_icon = pystray.Icon(
            name="AegisVault",
            icon=icon_img,
            title="AegisVault — Donanıma Kilitli Dosya Kasası",
            menu=self.build_tray_menu()
        )

        # Run tray in separate background thread
        tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True, name="AegisTray")
        tray_thread.start()

        # 3. Start GUI in Main Thread
        self.gui_app = AegisVaultApp(config_dir=APPDATA_DIR, default_vault_dir=DEFAULT_VAULT_DIR)

        # Minimize to tray on close
        self.gui_app.protocol("WM_DELETE_WINDOW", self.hide_gui)

        # Start Tkinter main loop
        self.gui_app.mainloop()


def main():
    parser = argparse.ArgumentParser(description="AegisVault Zero-Trust Security")
    parser.add_argument("--lock-direct", type=str, help="Belirtilen dosya veya klasörü anında mühürle ve imha et")
    args = parser.parse_args()

    if args.lock_direct:
        handle_direct_lock(args.lock_direct)
    else:
        controller = AegisVaultTrayController()
        controller.run()


if __name__ == "__main__":
    main()
