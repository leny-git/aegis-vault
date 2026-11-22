"""
AegisVault Modern Desktop GUI
Built with CustomTkinter.
Includes USB Key Setup Wizard, Vault Watcher Monitor, RAM Decryptor, and Emergency Panic Controls.
"""

import os
import sys
import threading
from typing import Optional, Callable

import customtkinter as ctk
from tkinter import filedialog, messagebox

from ..core.crypto_engine import (
    generate_rsa_keypair,
    save_public_key,
    load_public_key,
    encrypt_private_key_to_usb,
    load_private_key_from_usb,
    encrypt_file_stream,
    decrypt_file_to_ram,
    get_hardware_fingerprint
)
from ..core.shredder import shred_file, shred_directory
from ..services.watcher import VaultWatcherService
from ..services.usb_guard import USBDetector, DeadMansSwitch, PanicManager
from .ram_viewer import SecureRAMViewerWindow

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class AegisVaultApp(ctk.CTk):
    def __init__(self, config_dir: str, default_vault_dir: str):
        super().__init__()
        self.config_dir = config_dir
        self.default_vault_dir = default_vault_dir
        self.public_key_path = os.path.join(self.config_dir, "keys", "public.pem")

        self.title("🛡️ AegisVault — Sıfır-Güven Donanıma Kilitli Dosya Kasası")
        self.geometry("1100x750")
        self.minsize(900, 650)

        # Services
        self.active_private_key = None
        self.active_usb_key_path: Optional[str] = None
        self.dead_mans_switch = DeadMansSwitch(self.on_dead_man_triggered)
        self.watcher_service = VaultWatcherService(
            self.default_vault_dir,
            self.public_key_path,
            log_callback=self.log_event
        )

        # Register to PanicManager
        PanicManager.register_listener(self.on_panic_lockdown)

        self._build_layout()
        self._check_initial_state()

        # Start watcher automatically if public key exists
        if os.path.exists(self.public_key_path):
            self.watcher_service.start()
            self._update_status_badges()

    def _build_layout(self):
        # Grid setup
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar navigation
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#0b1120")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(7, weight=1)

        logo_label = ctk.CTkLabel(
            self.sidebar,
            text="AEGIS VAULT",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#38bdf8"
        )
        logo_label.grid(row=0, column=0, padx=20, pady=(25, 10))

        sub_label = ctk.CTkLabel(
            self.sidebar,
            text="v1.0 Zero-Trust Security",
            font=ctk.CTkFont(size=11),
            text_color="#64748b"
        )
        sub_label.grid(row=1, column=0, padx=20, pady=(0, 20))

        # Nav Buttons
        self.btn_nav_dashboard = ctk.CTkButton(
            self.sidebar, text="📊 Genel Bakış", fg_color="#1e293b", hover_color="#334155",
            anchor="w", command=lambda: self.show_view("dashboard")
        )
        self.btn_nav_dashboard.grid(row=2, column=0, padx=15, pady=5, sticky="ew")

        self.btn_nav_wizard = ctk.CTkButton(
            self.sidebar, text="🔑 USB Anahtar Kurulumu", fg_color="transparent", hover_color="#334155",
            anchor="w", command=lambda: self.show_view("wizard")
        )
        self.btn_nav_wizard.grid(row=3, column=0, padx=15, pady=5, sticky="ew")

        self.btn_nav_lock = ctk.CTkButton(
            self.sidebar, text="🔒 Dosya Kilitle & İmha Et", fg_color="transparent", hover_color="#334155",
            anchor="w", command=lambda: self.show_view("lock")
        )
        self.btn_nav_lock.grid(row=4, column=0, padx=15, pady=5, sticky="ew")

        self.btn_nav_unlock = ctk.CTkButton(
            self.sidebar, text="🔓 RAM'de Güvenli Aç", fg_color="transparent", hover_color="#334155",
            anchor="w", command=lambda: self.show_view("unlock")
        )
        self.btn_nav_unlock.grid(row=5, column=0, padx=15, pady=5, sticky="ew")

        # Emergency Panic Button in Sidebar Bottom
        self.panic_btn = ctk.CTkButton(
            self.sidebar,
            text="🚨 ACİL PANİK KİLİDİ\n(Ctrl+Alt+Shift+X)",
            fg_color="#ef4444",
            hover_color="#dc2626",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=50,
            command=lambda: PanicManager.trigger_panic("Kullanıcı Manuel Panik Butonuna Bastı")
        )
        self.panic_btn.grid(row=8, column=0, padx=15, pady=20, sticky="ew")

        # Main Content Views Container
        self.main_container = ctk.CTkFrame(self, corner_radius=0, fg_color="#020617")
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.main_container.grid_rowconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)

        # Build each view frame
        self.views = {}
        self.views["dashboard"] = self._create_dashboard_view()
        self.views["wizard"] = self._create_wizard_view()
        self.views["lock"] = self._create_lock_view()
        self.views["unlock"] = self._create_unlock_view()

        self.show_view("dashboard")

    def show_view(self, view_name: str):
        for name, frame in self.views.items():
            if name == view_name:
                frame.grid(row=0, column=0, sticky="nsew")
            else:
                frame.grid_forget()

        # Update button highlights
        buttons = {
            "dashboard": self.btn_nav_dashboard,
            "wizard": self.btn_nav_wizard,
            "lock": self.btn_nav_lock,
            "unlock": self.btn_nav_unlock,
        }
        for name, btn in buttons.items():
            btn.configure(fg_color="#1e293b" if name == view_name else "transparent")

    # ================= VIEW 1: DASHBOARD =================
    def _create_dashboard_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkScrollableFrame(self.main_container, fg_color="transparent")

        title = ctk.CTkLabel(frame, text="Sistem ve Güvenlik Durumu", font=ctk.CTkFont(size=22, weight="bold"), text_color="#f8fafc")
        title.pack(anchor="w", padx=20, pady=(20, 10))

        # Status Cards Frame
        cards_frame = ctk.CTkFrame(frame, fg_color="transparent")
        cards_frame.pack(fill="x", padx=20, pady=10)
        cards_frame.grid_columnconfigure((0, 1, 2), weight=1)

        # Card 1: Public Key
        self.card_pk = ctk.CTkFrame(cards_frame, fg_color="#0f172a", corner_radius=10, border_width=1, border_color="#1e293b")
        self.card_pk.grid(row=0, column=0, padx=5, sticky="ew")
        ctk.CTkLabel(self.card_pk, text="Bilgisayar Public Key", font=ctk.CTkFont(size=12, weight="bold"), text_color="#94a3b8").pack(pady=(12, 2))
        self.lbl_pk_status = ctk.CTkLabel(self.card_pk, text="Kontrol Ediliyor...", font=ctk.CTkFont(size=14, weight="bold"), text_color="#e2e8f0")
        self.lbl_pk_status.pack(pady=(0, 12))

        # Card 2: USB Hardware Key
        self.card_usb = ctk.CTkFrame(cards_frame, fg_color="#0f172a", corner_radius=10, border_width=1, border_color="#1e293b")
        self.card_usb.grid(row=0, column=1, padx=5, sticky="ew")
        ctk.CTkLabel(self.card_usb, text="USB Donanım Anahtarı", font=ctk.CTkFont(size=12, weight="bold"), text_color="#94a3b8").pack(pady=(12, 2))
        self.lbl_usb_status = ctk.CTkLabel(self.card_usb, text="Takılı Değil (Korumada)", font=ctk.CTkFont(size=14, weight="bold"), text_color="#f59e0b")
        self.lbl_usb_status.pack(pady=(0, 12))

        # Card 3: Vault Watcher
        self.card_watcher = ctk.CTkFrame(cards_frame, fg_color="#0f172a", corner_radius=10, border_width=1, border_color="#1e293b")
        self.card_watcher.grid(row=0, column=2, padx=5, sticky="ew")
        ctk.CTkLabel(self.card_watcher, text="7/24 Kasa İzleme", font=ctk.CTkFont(size=12, weight="bold"), text_color="#94a3b8").pack(pady=(12, 2))
        self.lbl_watcher_status = ctk.CTkLabel(self.card_watcher, text="Aktif Değil", font=ctk.CTkFont(size=14, weight="bold"), text_color="#ef4444")
        self.lbl_watcher_status.pack(pady=(0, 12))

        # Hardware Fingerprint Banner
        hw_fingerprint = get_hardware_fingerprint().hex()
        hw_box = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=8, border_width=1, border_color="#1e293b")
        hw_box.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(
            hw_box,
            text=f"🛡️ Bu Bilgisayarın Donanım Mührü (Hardware-Bound AAD SHA-256):\n{hw_fingerprint[:32]}...{hw_fingerprint[-16:]}",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color="#38bdf8",
            justify="left"
        ).pack(padx=15, pady=10)

        # Watcher controls
        watcher_box = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=8)
        watcher_box.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(watcher_box, text=f"📂 Kasa Klasörü: {self.default_vault_dir}", font=ctk.CTkFont(size=13, weight="bold")).pack(side="left", padx=15, pady=12)

        open_folder_btn = ctk.CTkButton(
            watcher_box, text="Klasörü Aç", width=100, fg_color="#334155",
            command=lambda: os.startfile(self.default_vault_dir) if os.path.exists(self.default_vault_dir) else None
        )
        open_folder_btn.pack(side="right", padx=10, pady=10)

        self.toggle_watcher_btn = ctk.CTkButton(
            watcher_box, text="İzlemeyi Durdur", width=120, fg_color="#0284c7",
            command=self._toggle_watcher
        )
        self.toggle_watcher_btn.pack(side="right", padx=5, pady=10)

        # Audit Log Box
        log_label = ctk.CTkLabel(frame, text="Canlı Güvenlik Denetim Günlüğü (Security Audit Log)", font=ctk.CTkFont(size=14, weight="bold"), text_color="#cbd5e1")
        log_label.pack(anchor="w", padx=20, pady=(15, 5))

        self.log_textbox = ctk.CTkTextbox(
            frame,
            height=250,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#050811",
            text_color="#10b981",
            border_width=1,
            border_color="#1e293b"
        )
        self.log_textbox.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.log_textbox.insert("1.0", "[AegisVault Engine] Sistem başlatıldı. Sıfır-güven çekirdeği aktif.\n")

        return frame

    # ================= VIEW 2: USB WIZARD =================
    def _create_wizard_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkScrollableFrame(self.main_container, fg_color="transparent")

        title = ctk.CTkLabel(frame, text="🔑 USB Donanım Anahtarı Kurulum Sihirbazı", font=ctk.CTkFont(size=22, weight="bold"), text_color="#f8fafc")
        title.pack(anchor="w", padx=20, pady=(20, 5))

        desc = ctk.CTkLabel(
            frame,
            text=(
                "Bu sihirbaz 4096-bit RSA anahtar çifti üretir.\n"
                "• Public Key bilgisayarınızda saklanarak arka planda parola sormadan otomatik kilitleme sağlar.\n"
                "• Private Key (Açma Anahtarı) Argon2id (64 MB bellek maliyetli) ile şifrelenip SADECE harici USB belleğe yazılır.\n"
                "• Bilgisayarınız hacklense dahi saldırgan Private Key'e fiziksel olarak erişemez!"
            ),
            font=ctk.CTkFont(size=13),
            text_color="#94a3b8",
            justify="left"
        )
        desc.pack(anchor="w", padx=20, pady=(0, 20))

        # Drive Selection
        ctk.CTkLabel(frame, text="1. USB Bellek Seçin:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(10, 5))

        drive_frame = ctk.CTkFrame(frame, fg_color="transparent")
        drive_frame.pack(fill="x", padx=20, pady=5)

        self.drive_combo = ctk.CTkComboBox(drive_frame, width=350, values=["Taranıyor..."])
        self.drive_combo.pack(side="left", padx=(0, 10))

        refresh_btn = ctk.CTkButton(drive_frame, text="🔄 Sürücüleri Yenile", width=140, command=self._refresh_drives)
        refresh_btn.pack(side="left")

        # Password Entry
        ctk.CTkLabel(frame, text="2. Ana Güvenlik Parolası Belirleyin (Argon2id):", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(20, 5))
        self.pass_entry = ctk.CTkEntry(frame, width=350, show="*", placeholder_text="En az 8 karakterli güçlü parola")
        self.pass_entry.pack(anchor="w", padx=20, pady=5)

        self.pass_confirm_entry = ctk.CTkEntry(frame, width=350, show="*", placeholder_text="Parolayı tekrar girin")
        self.pass_confirm_entry.pack(anchor="w", padx=20, pady=5)

        # Generate Button
        self.btn_generate_keys = ctk.CTkButton(
            frame,
            text="🚀 RSA-4096 Anahtarlarını Üret ve USB'ye Mühürle",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=45,
            fg_color="#059669",
            hover_color="#047857",
            command=self._generate_and_provision_keys
        )
        self.btn_generate_keys.pack(anchor="w", padx=20, pady=25)

        self._refresh_drives()
        return frame

    # ================= VIEW 3: LOCK FILE VIEW =================
    def _create_lock_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkScrollableFrame(self.main_container, fg_color="transparent")

        title = ctk.CTkLabel(frame, text="🔒 Manuel Dosya/Klasör Kilitle & Adli İmha Et", font=ctk.CTkFont(size=22, weight="bold"), text_color="#f8fafc")
        title.pack(anchor="w", padx=20, pady=(20, 5))

        desc = ctk.CTkLabel(
            frame,
            text="Herhangi bir dosyayı veya klasörü seçin. Dosya RSA-4096 + AES-256-GCM + Donanım Mührü ile şifrelenecek,\n"
                 "orijinal açık dosya ise 3 katmanlı üzerine yazma (0x00, 0xFF, os.urandom) ile diskten geri döndürülemez biçimde yok edilecektir.",
            font=ctk.CTkFont(size=13),
            text_color="#94a3b8",
            justify="left"
        )
        desc.pack(anchor="w", padx=20, pady=(0, 20))

        # File Select Box
        select_box = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=10)
        select_box.pack(fill="x", padx=20, pady=10)

        self.lock_target_entry = ctk.CTkEntry(select_box, width=500, placeholder_text="Kilitlemek istediğiniz dosya veya klasör yolu")
        self.lock_target_entry.pack(side="left", padx=15, pady=15, fill="x", expand=True)

        browse_file_btn = ctk.CTkButton(select_box, text="Dosya Seç", width=100, command=self._browse_lock_file)
        browse_file_btn.pack(side="left", padx=5, pady=15)

        browse_dir_btn = ctk.CTkButton(select_box, text="Klasör Seç", width=100, command=self._browse_lock_dir)
        browse_dir_btn.pack(side="left", padx=(5, 15), pady=15)

        # Lock Action Button
        self.btn_do_lock = ctk.CTkButton(
            frame,
            text="⚡ Mühürle ve Açık Kopyayı Parçala (Shred)",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=45,
            fg_color="#0284c7",
            hover_color="#0369a1",
            command=self._execute_manual_lock
        )
        self.btn_do_lock.pack(anchor="w", padx=20, pady=15)

        return frame

    # ================= VIEW 4: UNLOCK IN RAM =================
    def _create_unlock_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkScrollableFrame(self.main_container, fg_color="transparent")

        title = ctk.CTkLabel(frame, text="🔓 Disksiz RAM Çözme ve Güvenli Önizleyici", font=ctk.CTkFont(size=22, weight="bold"), text_color="#f8fafc")
        title.pack(anchor="w", padx=20, pady=(20, 5))

        desc = ctk.CTkLabel(
            frame,
            text="Şifreli .aegis dosyasını seçin ve USB anahtarınızın parolasını girin.\n"
                 "Dosya ASLA diske yazılmaz; doğrudan Windows VirtualLock ile kilitlenmiş RAM tamponuna çözülür.\n"
                 "USB bellek çekildiği milisaniyede tüm veriler RAM'den sıfırlanır ve pencereler imha edilir.",
            font=ctk.CTkFont(size=13),
            text_color="#94a3b8",
            justify="left"
        )
        desc.pack(anchor="w", padx=20, pady=(0, 20))

        # Aegis file selection
        file_box = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=10)
        file_box.pack(fill="x", padx=20, pady=10)

        self.unlock_target_entry = ctk.CTkEntry(file_box, width=500, placeholder_text="Açmak istediğiniz .aegis dosyasının yolu")
        self.unlock_target_entry.pack(side="left", padx=15, pady=15, fill="x", expand=True)

        browse_aegis_btn = ctk.CTkButton(file_box, text=".aegis Seç", width=110, command=self._browse_aegis_file)
        browse_aegis_btn.pack(side="left", padx=(5, 15), pady=15)

        # Password
        ctk.CTkLabel(frame, text="USB Anahtar Parolası:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=20, pady=(15, 5))
        self.unlock_pass_entry = ctk.CTkEntry(frame, width=350, show="*", placeholder_text="Master Parola")
        self.unlock_pass_entry.pack(anchor="w", padx=20, pady=5)

        # Decrypt Button
        self.btn_do_unlock = ctk.CTkButton(
            frame,
            text="👁️ RAM'de Aç ve Güvenli Görüntüle",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=45,
            fg_color="#10b981",
            hover_color="#059669",
            command=self._execute_ram_unlock
        )
        self.btn_do_unlock.pack(anchor="w", padx=20, pady=20)

        return frame

    # ================= LOGIC & HANDLERS =================
    def log_event(self, message: str):
        """Thread-safe event logging to the UI console."""
        def append():
            if hasattr(self, 'log_textbox'):
                self.log_textbox.insert("end", f"[{message}]\n")
                self.log_textbox.see("end")
        self.after(0, append)

    def _check_initial_state(self):
        pk_exists = os.path.exists(self.public_key_path)
        if pk_exists:
            self.lbl_pk_status.configure(text="Yüklü (Aktif)", text_color="#10b981")
        else:
            self.lbl_pk_status.configure(text="Eksik! (USB Kurulumu Yapın)", text_color="#ef4444")

        # Scan for USB key
        key_on_usb = USBDetector.find_key_on_removable_drives()
        if key_on_usb:
            self.lbl_usb_status.configure(text="USB Takılı (Anahtar Bulundu)", text_color="#38bdf8")
            self.log_event(f"🔑 USB Anahtarı Algılandı: {key_on_usb}")
        else:
            self.lbl_usb_status.configure(text="USB Takılı Değil (Korumada)", text_color="#f59e0b")

        if self.watcher_service.is_running():
            self.lbl_watcher_status.configure(text="Aktif (7/24 Koruma)", text_color="#10b981")
        else:
            self.lbl_watcher_status.configure(text="Durduruldu", text_color="#ef4444")

    def _update_status_badges(self):
        self._check_initial_state()

    def _refresh_drives(self):
        drives = USBDetector.get_removable_drives()
        if drives:
            vals = [d["label"] for d in drives]
            self.drive_combo.configure(values=vals)
            self.drive_combo.set(vals[0])
            self.log_event(f"USB sürücüleri tarandı: {len(drives)} çıkarılabilir cihaz bulundu.")
        else:
            self.drive_combo.configure(values=["Hiçbir USB Sürücüsü Bulunamadı"])
            self.drive_combo.set("Hiçbir USB Sürücüsü Bulunamadı")

    def _generate_and_provision_keys(self):
        password = self.pass_entry.get().strip()
        confirm = self.pass_confirm_entry.get().strip()

        if len(password) < 8:
            messagebox.showerror("Hata", "Güvenlik gereği ana parola en az 8 karakter olmalıdır!")
            return

        if password != confirm:
            messagebox.showerror("Hata", "Girdiğiniz parolalar birbiriyle uyuşmuyor!")
            return

        drives = USBDetector.get_removable_drives()
        selected_label = self.drive_combo.get()
        target_drive = next((d for d in drives if d["label"] == selected_label), None)

        if not target_drive:
            messagebox.showerror("Hata", "Lütfen geçerli bir USB bellek takıp listeden seçin!")
            return

        self.btn_generate_keys.configure(state="disabled", text="⏳ RSA-4096 & Argon2id Hesaplanıyor...")

        def worker():
            try:
                self.log_event("🔑 RSA-4096 anahtar çifti üretiliyor (Asimetrik Kriptografi)...")
                private_key, public_key = generate_rsa_keypair()

                # Save Public Key to PC
                self.log_event(f"💾 Public Key bilgisayara yazılıyor: {self.public_key_path}")
                save_public_key(public_key, self.public_key_path)

                # Encrypt Private Key with Argon2id + AES-256-GCM directly onto USB
                usb_key_dest = os.path.join(target_drive["mountpoint"], "aegis_key.vault")
                self.log_event(f"🔐 Private Key Argon2id (64 MB RAM cost) ile mühürleniyor: {usb_key_dest}")
                encrypt_private_key_to_usb(private_key, password, usb_key_dest)

                self.log_event("🎉 USB Anahtar Kurulumu Başarıyla Tamamlandı!")
                self.after(0, lambda: messagebox.showinfo(
                    "Başarılı",
                    "AegisVault USB Donanım Anahtarı başarıyla hazırlandı!\n\n"
                    f"Public Key: Bilgisayara kuruldu.\n"
                    f"Private Key: {usb_key_dest} adresine mühürlendi.\n\n"
                    "Şimdi dosyalarınızı parola sormadan kilitleyebilir, sadece bu USB takılıyken açabilirsiniz."
                ))

                # Auto-start watcher now that public key is present
                if not self.watcher_service.is_running():
                    self.watcher_service.start()

                self.after(0, self._update_status_badges)
                self.after(0, lambda: self.show_view("dashboard"))
            except Exception as e:
                self.log_event(f"❌ Anahtar Üretim Hatası: {str(e)}")
                self.after(0, lambda: messagebox.showerror("Hata", f"İşlem başarısız: {str(e)}"))
            finally:
                self.after(0, lambda: self.btn_generate_keys.configure(
                    state="normal", text="🚀 RSA-4096 Anahtarlarını Üret ve USB'ye Mühürle"
                ))

        threading.Thread(target=worker, daemon=True).start()

    def _toggle_watcher(self):
        if self.watcher_service.is_running():
            self.watcher_service.stop()
            self.toggle_watcher_btn.configure(text="İzlemeyi Başlat", fg_color="#10b981")
        else:
            if not os.path.exists(self.public_key_path):
                messagebox.showerror("Hata", "Önce USB Anahtar Kurulum Sihirbazı ile Public Key üretmelisiniz!")
                return
            self.watcher_service.start()
            self.toggle_watcher_btn.configure(text="İzlemeyi Durdur", fg_color="#0284c7")
        self._update_status_badges()

    def _browse_lock_file(self):
        f = filedialog.askopenfilename()
        if f:
            self.lock_target_entry.delete(0, "end")
            self.lock_target_entry.insert(0, f)

    def _browse_lock_dir(self):
        d = filedialog.askdirectory()
        if d:
            self.lock_target_entry.delete(0, "end")
            self.lock_target_entry.insert(0, d)

    def _execute_manual_lock(self):
        target = self.lock_target_entry.get().strip()
        if not target or not os.path.exists(target):
            messagebox.showerror("Hata", "Lütfen geçerli bir dosya veya klasör seçin!")
            return

        if not os.path.exists(self.public_key_path):
            messagebox.showerror("Hata", "Bilgisayarda Public Key bulunamadı! Önce anahtar kurulumunu yapın.")
            return

        self.btn_do_lock.configure(state="disabled", text="⏳ Şifreleniyor & İmha Ediliyor...")

        def worker():
            try:
                public_key = load_public_key(self.public_key_path)
                if os.path.isfile(target):
                    dest = target + ".aegis"
                    self.log_event(f"🔒 Manuel Kilitleme: {os.path.basename(target)}")
                    encrypt_file_stream(target, dest, public_key)
                    self.log_event(f"🔥 Adli İmha Başlatılıyor: {os.path.basename(target)}")
                    shred_file(target, passes=3)
                elif os.path.isdir(target):
                    import shutil
                    temp_zip = target + ".zip"
                    shutil.make_archive(target, 'zip', target)
                    dest = target + "_folder.aegis"
                    encrypt_file_stream(temp_zip, dest, public_key)
                    shred_file(temp_zip, passes=1)
                    shred_directory(target, passes=1)

                self.log_event(f"✅ Dosya Mühürlendi ve Orijinali Yok Edildi: {dest}")
                self.after(0, lambda: messagebox.showinfo(
                    "Mühürlendi",
                    f"Dosya başarıyla kilitlendi ve orijinal açık hali diskten geri döndürülemez biçimde yok edildi!\n\nKasa Dosyası: {dest}"
                ))
                self.after(0, lambda: self.lock_target_entry.delete(0, "end"))
            except Exception as e:
                self.log_event(f"❌ Kilitleme Hatası: {str(e)}")
                self.after(0, lambda: messagebox.showerror("Hata", f"Kilitleme başarısız: {str(e)}"))
            finally:
                self.after(0, lambda: self.btn_do_lock.configure(
                    state="normal", text="⚡ Mühürle ve Açık Kopyayı Parçala (Shred)"
                ))

        threading.Thread(target=worker, daemon=True).start()

    def _browse_aegis_file(self):
        f = filedialog.askopenfilename(filetypes=[("Aegis Vault Dosyası", "*.aegis"), ("Tüm Dosyalar", "*.*")])
        if f:
            self.unlock_target_entry.delete(0, "end")
            self.unlock_target_entry.insert(0, f)

    def _execute_ram_unlock(self):
        aegis_file = self.unlock_target_entry.get().strip()
        password = self.unlock_pass_entry.get().strip()

        if not aegis_file or not os.path.exists(aegis_file):
            messagebox.showerror("Hata", "Lütfen geçerli bir .aegis dosyası seçin!")
            return

        if not password:
            messagebox.showerror("Hata", "Lütfen USB Anahtar parolanızı girin!")
            return

        usb_key_path = USBDetector.find_key_on_removable_drives()
        if not usb_key_path:
            messagebox.showerror(
                "Donanım Hatası",
                "USB Anahtar takılı değil!\n"
                "Şifre çözme anahtarı bilgisayarda saklanmaz. Lütfen USB belleğinizi takın."
            )
            return

        self.btn_do_unlock.configure(state="disabled", text="⏳ RAM'de Çözülüyor...")

        def worker():
            try:
                self.log_event(f"🔑 USB Anahtar okunuyor: {usb_key_path}...")
                private_key = load_private_key_from_usb(usb_key_path, password)

                self.log_event(f"🛡️ Donanım Mührü doğrulanıyor & RAM'e çözülüyor...")
                secure_buffer, orig_name = decrypt_file_to_ram(aegis_file, private_key)

                self.log_event(f"✅ Çözüldü: {orig_name} ({secure_buffer.size} bayt). Diske ASLA yazılmadı.")

                # Arm Dead-Man's Switch
                self.active_usb_key_path = usb_key_path
                self.dead_mans_switch.arm(usb_key_path)
                self.log_event("⚡ Dead-Man's Switch Devrede: USB çıkarılırsa anında sıfırlanacak.")

                # Launch Secure RAM Viewer in main thread
                self.after(0, lambda: SecureRAMViewerWindow(self, secure_buffer, orig_name))
                self.after(0, lambda: self.unlock_pass_entry.delete(0, "end"))
            except PermissionError as pe:
                self.log_event(f"🚨 GÜVENLİK İHLALİ: {str(pe)}")
                self.after(0, lambda: messagebox.showerror("Donanım Uyuşmazlığı Reddedildi", str(pe)))
            except Exception as e:
                self.log_event(f"❌ Çözme Hatası: {str(e)}")
                self.after(0, lambda: messagebox.showerror("Hata", f"Şifre çözülemedi: {str(e)}"))
            finally:
                self.after(0, lambda: self.btn_do_unlock.configure(
                    state="normal", text="👁️ RAM'de Aç ve Güvenli Görüntüle"
                ))

        threading.Thread(target=worker, daemon=True).start()

    def on_dead_man_triggered(self, reason: str):
        """Called when USB is detached."""
        self.dead_mans_switch.disarm()
        PanicManager.trigger_panic(reason)

    def on_panic_lockdown(self, reason: str):
        """Emergency panic callback."""
        self.log_event(f"🚨 ACİL DURUM KİLİDİ: {reason}")
        self.dead_mans_switch.disarm()
        self.active_private_key = None
        self.active_usb_key_path = None
        self._update_status_badges()
        self.after(0, lambda: messagebox.showwarning(
            "Acil Durum Panik Kilidi",
            f"Kilit tetiklendi!\nSebep: {reason}\n\nRAM'deki tüm açık veriler sıfırlandı ve pencereler kapatıldı."
        ))
