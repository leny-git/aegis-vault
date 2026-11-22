"""
AegisVault Background Watcher Service
Watches designated Vault folder 24/7 using watchdog.
Automatically encrypts newly dropped files using the local RSA-4096 Public Key
without asking for passwords, and forensically shreds the original unencrypted file.
"""

import os
import sys
import time
import shutil
import zipfile
import threading
from typing import Optional, Callable

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileMovedEvent

from ..core.crypto_engine import encrypt_file_stream, load_public_key
from ..core.shredder import shred_file, shred_directory


class VaultDropHandler(FileSystemEventHandler):
    """Event handler that captures files/folders dropped into the Vault directory."""

    def __init__(self, public_key_path: str, log_callback: Optional[Callable[[str], None]] = None):
        super().__init__()
        self.public_key_path = public_key_path
        self.log_callback = log_callback
        self.processing_paths = set()
        self._lock = threading.Lock()

    def log(self, message: str):
        if self.log_callback:
            self.log_callback(message)
        else:
            print(f"[AegisWatcher] {message}")

    def on_created(self, event):
        self._handle_item(event.src_path)

    def on_moved(self, event):
        if isinstance(event, FileMovedEvent):
            self._handle_item(event.dest_path)

    def _handle_item(self, path: str):
        with self._lock:
            if path in self.processing_paths:
                return
            self.processing_paths.add(path)

        # Process in separate background thread to not block watchdog loop
        threading.Thread(target=self._process_worker, args=(path,), daemon=True).start()

    def _wait_for_file_stability(self, path: str, max_retries: int = 30) -> bool:
        """Ensures file is fully written and no longer locked by Windows Explorer/browser."""
        last_size = -1
        stable_count = 0

        for _ in range(max_retries):
            if not os.path.exists(path):
                return False
            try:
                current_size = os.path.getsize(path)
                if current_size == last_size and current_size > 0:
                    stable_count += 1
                    if stable_count >= 2:
                        # Try opening file to verify read handle
                        with open(path, "rb") as test_f:
                            test_f.read(10)
                        return True
                else:
                    stable_count = 0
                    last_size = current_size
            except (PermissionError, OSError):
                stable_count = 0

            time.sleep(0.5)
        return False

    def _process_worker(self, item_path: str):
        try:
            # Ignore already encrypted files or temporary files
            base_name = os.path.basename(item_path)
            if (
                base_name.endswith(".aegis") or
                base_name.endswith(".tmp") or
                base_name.endswith(".tmp_enc") or
                base_name.startswith("~$") or
                base_name.startswith(".aegis_")
            ):
                return

            time.sleep(0.8)  # Short debounce

            if not os.path.exists(item_path):
                return

            if not os.path.exists(self.public_key_path):
                self.log(f"UYARI: Public key ({self.public_key_path}) bulunamadı! Kilitleme atlandı.")
                return

            public_key = load_public_key(self.public_key_path)

            if os.path.isfile(item_path):
                # Wait for file copy to complete
                if not self._wait_for_file_stability(item_path):
                    self.log(f"HATA: Dosya kilitli veya tamamlanamadı: {base_name}")
                    return

                aegis_dest = item_path + ".aegis"
                self.log(f"🔒 Kilitleme Başladı: {base_name} (RSA-4096 + AES-256-GCM + Donanım Mührü)...")

                encrypt_file_stream(item_path, aegis_dest, public_key)
                self.log(f"✅ Mühürlendi: {os.path.basename(aegis_dest)}")

                # Forensic Shredding of original
                self.log(f"🔥 Adli İmha Başlatılıyor: {base_name}...")
                shred_file(item_path, passes=3)
                self.log(f"🛡️ İmha Tamamlandı. Dosya sadece Aegis Kasa formatında mevcut.")

            elif os.path.isdir(item_path):
                # Handle dropped folder: compress into container, encrypt, and shred original
                self.log(f"📁 Klasör Algılandı: {base_name}. Arşivlenip mühürleniyor...")
                temp_zip = item_path + ".zip"
                shutil.make_archive(item_path, 'zip', item_path)

                aegis_dest = item_path + "_folder.aegis"
                encrypt_file_stream(temp_zip, aegis_dest, public_key)
                shred_file(temp_zip, passes=1)

                self.log(f"🔥 Orijinal Klasör Adli İmha Ediliyor: {base_name}...")
                shred_directory(item_path, passes=1)
                self.log(f"🛡️ Klasör Tamamen Kilitlendi: {os.path.basename(aegis_dest)}")

        except Exception as e:
            self.log(f"❌ Kasa Hatası ({base_name}): {str(e)}")
        finally:
            with self._lock:
                self.processing_paths.discard(item_path)


class VaultWatcherService:
    """Manages the lifecycle of the watchdog directory observer."""

    def __init__(self, watch_dir: str, public_key_path: str, log_callback: Optional[Callable[[str], None]] = None):
        self.watch_dir = watch_dir
        self.public_key_path = public_key_path
        self.log_callback = log_callback
        self.observer: Optional[Observer] = None
        self._is_running = False

    def start(self):
        if self._is_running:
            return

        os.makedirs(self.watch_dir, exist_ok=True)
        event_handler = VaultDropHandler(self.public_key_path, self.log_callback)
        self.observer = Observer()
        self.observer.schedule(event_handler, self.watch_dir, recursive=False)
        self.observer.start()
        self._is_running = True
        if self.log_callback:
            self.log_callback(f"👁️ Kasa İzleme Servisi Aktif: {self.watch_dir}")

    def stop(self):
        if not self._is_running or not self.observer:
            return

        self.observer.stop()
        self.observer.join(timeout=3)
        self._is_running = False
        if self.log_callback:
            self.log_callback("🛑 Kasa İzleme Servisi Durduruldu.")

    def is_running(self) -> bool:
        return self._is_running
