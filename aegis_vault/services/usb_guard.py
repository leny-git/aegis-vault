"""
AegisVault USB Guard & Dead-Man's Switch Service
Monitors USB hardware presence every 500ms.
Triggers immediate RAM purge and window shutdown if USB is pulled or Panic Hotkey (Ctrl+Alt+Shift+X) is pressed.
"""

import os
import sys
import time
import ctypes
import threading
from typing import List, Optional, Callable, Dict

import psutil
from ..core.crypto_engine import ActiveBufferRegistry

# Windows Drive Type API
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3

kernel32 = ctypes.windll.kernel32
GetDriveTypeW = kernel32.GetDriveTypeW
GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
GetDriveTypeW.restype = ctypes.c_uint


class USBDetector:
    """Detects connected removable USB flash drives and locates AegisVault keys."""

    @staticmethod
    def get_removable_drives() -> List[Dict[str, str]]:
        """Returns a list of removable drives with drive letter and label."""
        drives = []
        for part in psutil.disk_partitions(all=False):
            try:
                drive_letter = part.mountpoint.rstrip("\\") + "\\"
                dtype = GetDriveTypeW(drive_letter)
                # DRIVE_REMOVABLE or opts containing removable
                if dtype == DRIVE_REMOVABLE or "removable" in part.opts.lower():
                    # Check volume name
                    vol_buf = ctypes.create_unicode_buffer(261)
                    fs_buf = ctypes.create_unicode_buffer(261)
                    kernel32.GetVolumeInformationW(
                        drive_letter, vol_buf, 261, None, None, None, fs_buf, 261
                    )
                    label = vol_buf.value or "USB Sürücüsü"
                    drives.append({
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "label": f"{label} ({part.mountpoint})"
                    })
            except Exception:
                continue
        return drives

    @staticmethod
    def find_key_on_removable_drives(filename: str = "aegis_key.vault") -> Optional[str]:
        """Scans all removable drives for the presence of the key file."""
        for drive in USBDetector.get_removable_drives():
            key_candidate = os.path.join(drive["mountpoint"], filename)
            if os.path.exists(key_candidate):
                return key_candidate
        return None


class DeadMansSwitch:
    """
    Sub-second hardware watchdog.
    Continuously validates that the authorized USB key is connected.
    If the USB drive is detached, triggers Panic Lockdown within 500ms.
    """

    def __init__(self, panic_callback: Callable[[str], None]):
        self.panic_callback = panic_callback
        self.monitored_key_path: Optional[str] = None
        self._is_armed = False
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def arm(self, key_path: str):
        """Arms the dead-man's switch to watch a specific USB key path."""
        with self._lock:
            self.monitored_key_path = key_path
            self._is_armed = True
            if not self._running:
                self.start()

    def disarm(self):
        """Disarms monitoring when vault session is voluntarily locked."""
        with self._lock:
            self._is_armed = False
            self.monitored_key_path = None

    def is_armed(self) -> bool:
        with self._lock:
            return self._is_armed

    def start(self):
        """Starts the background sensor loop."""
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="AegisDeadMansSwitch")
        self._thread.start()

    def stop(self):
        self._running = False
        self.disarm()

    def _monitor_loop(self):
        """500ms hardware polling loop."""
        while self._running:
            try:
                time.sleep(0.5)
                with self._lock:
                    if not self._is_armed or not self.monitored_key_path:
                        continue

                    key_exists = False
                    try:
                        # Attempt to check file existence and readability
                        if os.path.exists(self.monitored_key_path):
                            # Ensure drive didn't disconnect midway
                            with open(self.monitored_key_path, "rb") as test_f:
                                test_f.read(16)
                            key_exists = True
                    except Exception:
                        key_exists = False

                    if not key_exists:
                        # USB PULLED! TRIGGER EMERGENCY PANIC
                        self._is_armed = False
                        self.monitored_key_path = None
                        threading.Thread(
                            target=self.panic_callback,
                            args=("DEAD_MANS_SWITCH: USB Bellek Çekildi! Acil Durum RAM Temizliği Başlatıldı.",),
                            daemon=True
                        ).start()
            except Exception:
                pass


class PanicManager:
    """Coordinates panic lockouts, RAM scrubbing, and viewer closures."""
    _listeners: List[Callable[[str], None]] = []
    _lock = threading.Lock()

    @classmethod
    def register_listener(cls, callback: Callable[[str], None]):
        with cls._lock:
            if callback not in cls._listeners:
                cls._listeners.append(callback)

    @classmethod
    def unregister_listener(cls, callback: Callable[[str], None]):
        with cls._lock:
            if callback in cls._listeners:
                cls._listeners.remove(callback)

    @classmethod
    def trigger_panic(cls, reason: str = "Kullanıcı Panik Kilidi veya USB Çekilmesi"):
        """
        1. Overwrites all decrypted memory buffers with zeros (ctypes.memset).
        2. Closes all secure preview windows.
        3. Clears loaded crypto keys from memory.
        4. Notifies listeners.
        """
        # 1. Immediate RAM zeroization
        ActiveBufferRegistry.wipe_all()

        # 2. Notify all registered UI components & services
        with cls._lock:
            for listener in cls._listeners:
                try:
                    listener(reason)
                except Exception:
                    pass


def start_panic_hotkey_listener(callback: Callable[[str], None]):
    """
    Spawns background listener for global shortcut: Ctrl + Alt + Shift + X
    Uses Windows RegisterHotKey or ctypes message pump.
    """
    def hotkey_thread():
        user32 = ctypes.windll.user32
        MOD_ALT = 0x0001
        MOD_CONTROL = 0x0002
        MOD_SHIFT = 0x0004
        VK_X = 0x58
        HOTKEY_ID = 9999

        if not user32.RegisterHotKey(None, HOTKEY_ID, MOD_CONTROL | MOD_ALT | MOD_SHIFT, VK_X):
            return

        msg = ctypes.wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
            if msg.message == 0x0312:  # WM_HOTKEY
                if msg.wParam == HOTKEY_ID:
                    PanicManager.trigger_panic("PANİK KISAYOLU (Ctrl+Alt+Shift+X) TETİKLENDİ!")
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        user32.UnregisterHotKey(None, HOTKEY_ID)

    t = threading.Thread(target=hotkey_thread, daemon=True, name="AegisPanicHotkey")
    t.start()
