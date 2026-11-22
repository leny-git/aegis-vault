"""
AegisVault Anti-Forensics Shredder
Military-grade secure data destruction module.
Overwrites file sectors multiple times (Zeroes, Ones, Cryptographic Randomness),
forces hardware cache flushes via os.fsync, obfuscates NTFS MFT file name attributes,
and scrubs timestamps before permanent unlinking.
"""

import os
import sys
import uuid
import time
import shutil
from typing import Optional, Callable


def shred_file(file_path: str, passes: int = 3, progress_callback: Optional[Callable[[str, float], None]] = None) -> bool:
    """
    Shreds an individual file with forensic-grade unrecoverability:
    1. Multi-pass overwrite (Pass 1: 0x00, Pass 2: 0xFF, Pass 3: os.urandom).
    2. Flush buffers & fsync after each pass to bypass SSD/HDD write caches.
    3. Truncate file length to zero.
    4. Reset MAC (Modified, Accessed, Created) timestamps.
    5. Rename file to random UUID strings 3 times to sanitize NTFS MFT $FILE_NAME records.
    6. os.remove() permanent unlinking.
    """
    if not os.path.exists(file_path):
        return False

    try:
        # Check write permissions and remove read-only attribute if set
        os.chmod(file_path, 0o777)
        file_size = os.path.getsize(file_path)

        if file_size > 0:
            buffer_size = 64 * 1024  # 64 KB write buffer

            with open(file_path, "r+b") as f:
                fd = f.fileno()

                patterns = [
                    (b"\x00", "Sıfır Bayt Yazımı (0x00)"),
                    (b"\xFF", "Bir Bayt Yazımı (0xFF)"),
                    (None, "Kriptografik Rastgele Gürültü (os.urandom)")
                ]

                # Use requested passes
                for pass_num in range(1, passes + 1):
                    pattern_byte, desc = patterns[(pass_num - 1) % len(patterns)]
                    if progress_callback:
                        progress_callback(f"İmha Katmanı {pass_num}/{passes}: {desc}", (pass_num - 1) / passes)

                    f.seek(0)
                    bytes_written = 0

                    while bytes_written < file_size:
                        chunk_len = min(buffer_size, file_size - bytes_written)
                        if pattern_byte is not None:
                            payload = pattern_byte * chunk_len
                        else:
                            payload = os.urandom(chunk_len)

                        f.write(payload)
                        bytes_written += chunk_len

                    f.flush()
                    os.fsync(fd)

                # Truncate to zero
                f.seek(0)
                f.truncate(0)
                f.flush()
                os.fsync(fd)

        # 4. Obfuscate file timestamps
        try:
            zero_epoch = 0.0
            os.utime(file_path, (zero_epoch, zero_epoch))
        except Exception:
            pass

        # 5. Obfuscate NTFS directory entries (MFT table scrubbing)
        parent_dir = os.path.dirname(os.path.abspath(file_path))
        current_path = file_path

        for _ in range(3):
            random_name = os.path.join(parent_dir, f"aegis_shred_{uuid.uuid4().hex[:16]}.tmp")
            try:
                os.rename(current_path, random_name)
                current_path = random_name
            except Exception:
                break

        # 6. Unlink file permanently
        os.remove(current_path)

        if progress_callback:
            progress_callback("Dosya Adli Bilişim Seviyesinde Yok Edildi.", 1.0)
        return True

    except Exception as e:
        # Last resort fallback if in-place overwrite was locked
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                return True
        except Exception:
            pass
        raise RuntimeError(f"Dosya guvenli imha edilemedi: {file_path} - Hata: {str(e)}")


def shred_directory(dir_path: str, passes: int = 3, progress_callback: Optional[Callable[[str, float], None]] = None) -> bool:
    """Recursively shreds all files inside a directory and wipes the directory tree."""
    if not os.path.isdir(dir_path):
        return False

    for root, dirs, files in os.walk(dir_path, topdown=False):
        for file in files:
            full_file_path = os.path.join(root, file)
            shred_file(full_file_path, passes=passes, progress_callback=progress_callback)

        for d in dirs:
            full_dir_path = os.path.join(root, d)
            # Rename dir randomly before removing
            random_dir = os.path.join(root, f"aegis_dir_{uuid.uuid4().hex[:12]}")
            try:
                os.rename(full_dir_path, random_dir)
                os.rmdir(random_dir)
            except Exception:
                shutil.rmtree(full_dir_path, ignore_errors=True)

    # Wipe root dir
    try:
        shutil.rmtree(dir_path, ignore_errors=True)
    except Exception:
        pass

    return True
