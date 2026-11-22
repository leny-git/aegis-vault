"""
AegisVault Secure RAM Viewer
Zero-Disk Footprint viewer for decrypted documents, images, code, PDFs, and FOLDERS.
Includes In-Memory Folder & Archive Explorer (ZipFile in RAM), file previewer,
and Secure Export / Decrypt-to-Disk capabilities.
"""

import os
import io
import sys
import ctypes
import zipfile
from typing import List, Optional, Dict

import customtkinter as ctk
from PIL import Image, ImageTk
import fitz  # PyMuPDF
from tkinter import filedialog, messagebox

from ..core.crypto_engine import SecureBuffer
from ..services.usb_guard import PanicManager

WDA_MONITOR = 0x00000001
WDA_EXCLUDEFROMCAPTURE = 0x00000011


def apply_anti_screen_capture(window: ctk.CTkToplevel):
    """Prevents RATs, screen recorders, and capture malware from viewing this window."""
    try:
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        if hwnd == 0:
            hwnd = window.winfo_id()
        res = ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
        if res == 0:
            ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, WDA_MONITOR)
    except Exception:
        pass


class SecureViewerRegistry:
    """Tracks active RAM viewers so Panic can destroy them instantly."""
    _viewers: List['SecureRAMViewerWindow'] = []

    @classmethod
    def register(cls, viewer: 'SecureRAMViewerWindow'):
        cls._viewers.append(viewer)

    @classmethod
    def unregister(cls, viewer: 'SecureRAMViewerWindow'):
        if viewer in cls._viewers:
            cls._viewers.remove(viewer)

    @classmethod
    def close_all(cls):
        """Immediately destroys all viewer windows on panic."""
        for v in list(cls._viewers):
            try:
                v.force_wipe_and_close()
            except Exception:
                pass
        cls._viewers.clear()


class SecureRAMViewerWindow(ctk.CTkToplevel):
    def __init__(self, master, secure_buffer: SecureBuffer, original_filename: str):
        super().__init__(master)
        self.secure_buffer = secure_buffer
        self.original_filename = original_filename
        self.ext = os.path.splitext(original_filename)[1].lower()

        # Window configuration
        self.title(f"🛡️ AegisVault RAM Önizleyici [SIFIR DİSK] — {original_filename}")
        self.geometry("1050x720")
        self.minsize(800, 550)

        # Apply Anti-Capture
        self.after(100, lambda: apply_anti_screen_capture(self))

        # Register to registries
        SecureViewerRegistry.register(self)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self._build_ui()
        self._load_content()

    def _build_ui(self):
        # Top Header Bar
        self.header_frame = ctk.CTkFrame(self, height=50, corner_radius=0, fg_color="#0f172a")
        self.header_frame.pack(side="top", fill="x")

        size_kb = self.secure_buffer.size / 1024
        title_lbl = ctk.CTkLabel(
            self.header_frame,
            text=f"🔒 {self.original_filename} ({size_kb:.1f} KB - RAM'de Kilitli)",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#38bdf8"
        )
        title_lbl.pack(side="left", padx=20, pady=10)

        # Panic/Wipe Button
        self.wipe_btn = ctk.CTkButton(
            self.header_frame,
            text="🚨 RAM'i Sıfırla ve Kapat",
            fg_color="#ef4444",
            hover_color="#dc2626",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self.on_close
        )
        self.wipe_btn.pack(side="right", padx=15, pady=10)

        # Export to Disk Button
        self.export_btn = ctk.CTkButton(
            self.header_frame,
            text="💾 Diske Çıkar (Kurtar)",
            fg_color="#059669",
            hover_color="#047857",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._export_to_disk
        )
        self.export_btn.pack(side="right", padx=5, pady=10)

        # Main Content Container
        self.content_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="#020617")
        self.content_frame.pack(side="top", fill="both", expand=True)

    def _load_content(self):
        data = self.secure_buffer.get_bytes()

        # 1. Check Magic Bytes for ZIP / Folder container (PK\x03\x04)
        if data[:4] == b"PK\x03\x04" or self.ext in [".zip", ".folder"] or "_folder" in self.original_filename:
            self._render_folder_explorer(data)
            return

        # 2. Check Magic Bytes for Image Formats
        is_image_magic = (
            data[:8] == b"\x89PNG\r\n\x1a\n" or  # PNG
            data[:2] == b"\xff\xd8" or            # JPEG
            data[:4] == b"GIF8" or                # GIF
            data[:2] == b"BM" or                  # BMP
            data[:4] == b"RIFF"                   # WEBP
        )

        if is_image_magic or self.ext in [".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"]:
            self._render_image(data)
        # 3. PDF Document
        elif data[:4] == b"%PDF" or self.ext == ".pdf":
            self._render_pdf(data)
        # 4. Text / Code / General
        else:
            try:
                text_content = data.decode("utf-8")
                self._render_text(text_content)
            except UnicodeDecodeError:
                self._render_hex_dump(data)

    # ================= FOLDER / ARCHIVE EXPLORER =================
    def _render_folder_explorer(self, data: bytes):
        """Interactive In-RAM Folder & Archive Explorer."""
        try:
            zip_stream = io.BytesIO(data)
            zf = zipfile.ZipFile(zip_stream, "r")
            file_list = [f for f in zf.infolist() if not f.is_dir()]
        except Exception as e:
            self._render_text(f"Arşiv okunamadı: {str(e)}")
            return

        # Split pane: Left file list, Right preview pane
        pane = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        pane.pack(fill="both", expand=True)
        pane.grid_columnconfigure(1, weight=1)
        pane.grid_rowconfigure(0, weight=1)

        # Left Sidebar (Files List)
        sidebar = ctk.CTkFrame(pane, width=280, fg_color="#0b1120", corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_rowconfigure(2, weight=1)

        header_lbl = ctk.CTkLabel(
            sidebar,
            text=f"📁 Kasa Klasörü ({len(file_list)} dosya)",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#38bdf8"
        )
        header_lbl.grid(row=0, column=0, padx=15, pady=(15, 5), sticky="w")

        # Extract All Button
        extract_all_btn = ctk.CTkButton(
            sidebar,
            text="📂 Tüm Klasörü Dışa Aktar",
            fg_color="#0284c7",
            hover_color="#0369a1",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=lambda: self._export_entire_folder(zf)
        )
        extract_all_btn.grid(row=1, column=0, padx=15, pady=8, sticky="ew")

        # Scrollable file list
        files_scroll = ctk.CTkScrollableFrame(sidebar, fg_color="transparent")
        files_scroll.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)

        # Right Preview Area
        preview_container = ctk.CTkFrame(pane, fg_color="#020617", corner_radius=0)
        preview_container.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

        active_btn = [None]

        def open_file_in_preview(file_info: zipfile.ZipInfo, clicked_btn):
            if active_btn[0]:
                active_btn[0].configure(fg_color="transparent")
            clicked_btn.configure(fg_color="#1e293b")
            active_btn[0] = clicked_btn

            # Clear preview container
            for widget in preview_container.winfo_children():
                widget.destroy()

            try:
                raw_bytes = zf.read(file_info.filename)
                fname = os.path.basename(file_info.filename)
                fext = os.path.splitext(fname)[1].lower()

                # Preview header
                bar = ctk.CTkFrame(preview_container, height=35, fg_color="#111827")
                bar.pack(fill="x", side="top", padx=5, pady=5)

                ctk.CTkLabel(
                    bar,
                    text=f"📄 {file_info.filename} ({len(raw_bytes)/1024:.1f} KB)",
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color="#f8fafc"
                ).pack(side="left", padx=15)

                # Export single file button
                ctk.CTkButton(
                    bar,
                    text="💾 Bu Dosyayı Kaydet",
                    width=130,
                    fg_color="#059669",
                    hover_color="#047857",
                    font=ctk.CTkFont(size=11, weight="bold"),
                    command=lambda: self._export_single_file(fname, raw_bytes)
                ).pack(side="right", padx=10, pady=5)

                # Render preview
                is_img = (
                    raw_bytes[:8] == b"\x89PNG\r\n\x1a\n" or
                    raw_bytes[:2] == b"\xff\xd8" or
                    raw_bytes[:4] == b"GIF8" or
                    fext in [".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"]
                )

                if is_img:
                    self._render_image_on_frame(raw_bytes, preview_container)
                elif raw_bytes[:4] == b"%PDF" or fext == ".pdf":
                    self._render_pdf_on_frame(raw_bytes, preview_container)
                else:
                    try:
                        text_str = raw_bytes.decode("utf-8")
                        self._render_text_on_frame(text_str, preview_container)
                    except UnicodeDecodeError:
                        self._render_hex_dump_on_frame(raw_bytes, preview_container)
            except Exception as ex:
                lbl = ctk.CTkLabel(preview_container, text=f"Dosya okuma hatası: {str(ex)}", text_color="#ef4444")
                lbl.pack(padx=20, pady=20)

        # Populate file items
        for info in file_list:
            display_name = info.filename
            size_str = f"{info.file_size / 1024:.1f} KB"
            btn = ctk.CTkButton(
                files_scroll,
                text=f"📄 {display_name}\n    ({size_str})",
                anchor="w",
                fg_color="transparent",
                hover_color="#1e293b",
                font=ctk.CTkFont(family="Consolas", size=12),
                height=45
            )
            btn.configure(command=lambda i=info, b=btn: open_file_in_preview(i, b))
            btn.pack(fill="x", pady=2)

        # Automatically open the first file
        if file_list:
            first_btn = files_scroll.winfo_children()[0]
            open_file_in_preview(file_list[0], first_btn)

    def _export_entire_folder(self, zf: zipfile.ZipFile):
        target_dir = filedialog.askdirectory(title="Klasörün Çıkarılacağı Konumu Seçin")
        if not target_dir:
            return
        try:
            zf.extractall(target_dir)
            messagebox.showinfo("Başarılı", f"Tüm dosyalar başarıyla çıkarıldı:\n{target_dir}")
        except Exception as e:
            messagebox.showerror("Hata", f"Dışa aktarma başarısız: {str(e)}")

    def _export_single_file(self, filename: str, data: bytes):
        dest = filedialog.asksaveasfilename(initialfile=filename, title="Dosyayı Kaydet")
        if not dest:
            return
        try:
            with open(dest, "wb") as f:
                f.write(data)
            messagebox.showinfo("Başarılı", f"Dosya başarıyla kaydedildi:\n{dest}")
        except Exception as e:
            messagebox.showerror("Hata", f"Kaydetme başarısız: {str(e)}")

    def _export_to_disk(self):
        """Exports the entire currently decrypted buffer to a chosen file or folder."""
        data = self.secure_buffer.get_bytes()
        is_zip = data[:4] == b"PK\x03\x04" or "_folder" in self.original_filename

        if is_zip:
            target_dir = filedialog.askdirectory(title="Klasörün Çıkarılacağı Konumu Seçin")
            if not target_dir:
                return
            try:
                with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                    zf.extractall(target_dir)
                messagebox.showinfo("Başarılı", f"Klasör içeriği başarıyla çıkarıldı:\n{target_dir}")
            except Exception as e:
                messagebox.showerror("Hata", f"Çıkarma hatası: {str(e)}")
        else:
            clean_name = self.original_filename
            dest = filedialog.asksaveasfilename(initialfile=clean_name, title="Dosyayı Kaydet")
            if not dest:
                return
            try:
                with open(dest, "wb") as f:
                    f.write(data)
                messagebox.showinfo("Başarılı", f"Dosya başarıyla diske kaydedildi:\n{dest}")
            except Exception as e:
                messagebox.showerror("Hata", f"Kaydetme hatası: {str(e)}")

    # ================= SUB-RENDERERS =================
    def _render_text(self, text: str):
        self._render_text_on_frame(text, self.content_frame)

    def _render_text_on_frame(self, text: str, parent):
        textbox = ctk.CTkTextbox(
            parent,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color="#090d16",
            text_color="#e2e8f0"
        )
        textbox.pack(fill="both", expand=True, padx=10, pady=10)
        textbox.insert("1.0", text)
        textbox.configure(state="disabled")

    def _render_image(self, data: bytes):
        self._render_image_on_frame(data, self.content_frame)

    def _render_image_on_frame(self, data: bytes, parent):
        try:
            image_stream = io.BytesIO(data)
            pil_img = Image.open(image_stream)
            pil_img.load()

            # Ensure valid mode for Tkinter
            if pil_img.mode not in ("RGB", "RGBA"):
                pil_img = pil_img.convert("RGBA")

            max_w, max_h = 750, 550
            orig_w, orig_h = pil_img.size
            scale = min(max_w / orig_w, max_h / orig_h, 1.0)
            new_size = (max(1, int(orig_w * scale)), max(1, int(orig_h * scale)))

            ctk_image = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=new_size)

            lbl = ctk.CTkLabel(parent, text="", image=ctk_image)
            lbl.image = ctk_image
            lbl.pack(expand=True, fill="both", padx=10, pady=10)
        except Exception as e:
            self._render_text_on_frame(f"Görsel RAM tamponundan çözülemedi: {str(e)}", parent)

    def _render_pdf(self, data: bytes):
        self._render_pdf_on_frame(data, self.content_frame)

    def _render_pdf_on_frame(self, data: bytes, parent):
        try:
            doc = fitz.open(stream=data, filetype="pdf")
            total_pages = len(doc)
            current_page_idx = [0]

            nav_frame = ctk.CTkFrame(parent, height=40, fg_color="#1e293b")
            nav_frame.pack(side="top", fill="x", padx=10, pady=5)

            page_label = ctk.CTkLabel(
                nav_frame,
                text=f"Sayfa: 1 / {total_pages}",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color="#f8fafc"
            )
            page_label.pack(side="left", padx=20)

            img_label = ctk.CTkLabel(parent, text="")
            img_label.pack(expand=True, fill="both", padx=10, pady=10)

            def update_page():
                page = doc.load_page(current_page_idx[0])
                pix = page.get_pixmap(dpi=150)
                img = Image.open(io.BytesIO(pix.tobytes("png")))
                max_w, max_h = 750, 520
                scale = min(max_w / img.width, max_h / img.height, 1.0)
                new_size = (int(img.width * scale), int(img.height * scale))
                ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=new_size)
                img_label.configure(image=ctk_img)
                img_label.image = ctk_img
                page_label.configure(text=f"Sayfa: {current_page_idx[0] + 1} / {total_pages}")

            def prev_page():
                if current_page_idx[0] > 0:
                    current_page_idx[0] -= 1
                    update_page()

            def next_page():
                if current_page_idx[0] < total_pages - 1:
                    current_page_idx[0] += 1
                    update_page()

            ctk.CTkButton(nav_frame, text="◀ Önceki", width=80, command=prev_page).pack(side="left", padx=5)
            ctk.CTkButton(nav_frame, text="Sonraki ▶", width=80, command=next_page).pack(side="left", padx=5)

            update_page()
        except Exception as e:
            self._render_text_on_frame(f"PDF RAM tamponundan yüklenemedi: {str(e)}", parent)

    def _render_hex_dump(self, data: bytes):
        self._render_hex_dump_on_frame(data, self.content_frame)

    def _render_hex_dump_on_frame(self, data: bytes, parent):
        lines = []
        preview_len = min(len(data), 16 * 1024)
        for i in range(0, preview_len, 16):
            chunk = data[i:i + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:08X}  {hex_part:<48}  |{ascii_part}|")

        if len(data) > preview_len:
            lines.append(f"\n[... Toplam {len(data)} bayt. İlk 16 KB RAM dökümü gösterildi ...]")

        self._render_text_on_frame("\n".join(lines), parent)

    def force_wipe_and_close(self):
        """Called by Dead-Man's Switch to immediately close window and zeroize RAM."""
        try:
            self.secure_buffer.wipe()
        except Exception:
            pass
        finally:
            try:
                self.destroy()
            except Exception:
                pass

    def on_close(self):
        SecureViewerRegistry.unregister(self)
        self.force_wipe_and_close()


# Connect viewer registry to PanicManager
PanicManager.register_listener(lambda reason: SecureViewerRegistry.close_all())
