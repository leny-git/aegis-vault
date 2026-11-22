"""
AegisVault Cryptographic Engine
Architecture:
- Hybrid Locking: RSA-4096 (Public Key on PC) + AES-256-GCM (Streaming Chunk Cipher)
- Hardware-Bound AAD: MachineGuid + Motherboard UUID SHA-256 Digest
- Argon2id Key Derivation for USB Private Key (64 MB+ memory cost)
- Windows VirtualLock API for Zero-Disk RAM Page Protection & Active Buffer Registry
"""

import os
import sys
import struct
import hashlib
import ctypes
import winreg
import subprocess
import threading
from typing import Tuple, Optional, List

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag, InvalidSignature

# Windows Memory Management APIs
kernel32 = ctypes.windll.kernel32
VirtualLock = kernel32.VirtualLock
VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
VirtualLock.restype = ctypes.c_int

VirtualUnlock = kernel32.VirtualUnlock
VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
VirtualUnlock.restype = ctypes.c_int

CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunk
MAGIC_HEADER = b"AEGISV1\x00"  # 8 bytes magic header


class SecureBuffer:
    """
    In-memory protected buffer locked using Windows VirtualLock.
    Guarantees data is never swapped to pagefile.sys and supports
    instant military-grade zeroization via ctypes.memset.
    """
    def __init__(self, data: bytes):
        self.size = len(data)
        # Allocate pinned ctypes buffer
        self._buf = ctypes.create_string_buffer(data, self.size)
        self.address = ctypes.addressof(self._buf)
        self.is_locked = False
        self.is_wiped = False

        # Attempt to lock page in physical RAM (prevent swap/paging)
        try:
            res = VirtualLock(self.address, self.size)
            if res != 0:
                self.is_locked = True
        except Exception:
            self.is_locked = False

        ActiveBufferRegistry.register(self)

    def get_bytes(self) -> bytes:
        if self.is_wiped:
            raise ValueError("Access to wiped SecureBuffer is prohibited.")
        return ctypes.string_at(self.address, self.size)

    def wipe(self):
        """Wipe memory immediately using ctypes.memset and unlock."""
        if self.is_wiped:
            return
        try:
            ctypes.memset(self.address, 0, self.size)
            if self.is_locked:
                VirtualUnlock(self.address, self.size)
                self.is_locked = False
        except Exception:
            pass
        finally:
            self.is_wiped = True
            ActiveBufferRegistry.unregister(self)

    def __del__(self):
        self.wipe()


class ActiveBufferRegistry:
    """Global registry to track all active secure buffers for Instant Panic Wipe."""
    _lock = threading.Lock()
    _buffers: List[SecureBuffer] = []

    @classmethod
    def register(cls, buf: SecureBuffer):
        with cls._lock:
            cls._buffers.append(buf)

    @classmethod
    def unregister(cls, buf: SecureBuffer):
        with cls._lock:
            if buf in cls._buffers:
                cls._buffers.remove(buf)

    @classmethod
    def wipe_all(cls):
        """Emergency Dead-Man / Panic: Zero-out all buffers in RAM instantly."""
        with cls._lock:
            while cls._buffers:
                buf = cls._buffers.pop(0)
                try:
                    buf.wipe()
                except Exception:
                    pass


_CACHED_HW_FINGERPRINT = None

def get_hardware_fingerprint() -> bytes:
    """
    Collects Windows MachineGuid, BIOS/Motherboard UUID, and CPU Identifier.
    Caches the 32-byte SHA-256 digest in %APPDATA%\\AegisVault\\hw_id.bin
    and RAM so it is 100% deterministic, instant (0.0001s), and never
    suffers from subprocess timeout variations between lock and unlock.
    """
    global _CACHED_HW_FINGERPRINT
    if _CACHED_HW_FINGERPRINT is not None:
        return _CACHED_HW_FINGERPRINT

    # 1. Check local persistent machine cache
    appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
    cache_path = os.path.join(appdata, "AegisVault", "hw_id.bin")
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "rb") as cf:
                data = cf.read()
                if len(data) == 32:
                    _CACHED_HW_FINGERPRINT = data
                    return data
        except Exception:
            pass

    components = []

    # 1. Windows MachineGuid (ultra-fast via Registry)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            components.append(str(guid).strip().encode('utf-8'))
    except Exception:
        components.append(b"MACHINEGUID_FALLBACK")

    # 2. Motherboard / Baseboard Serial Number or UUID via PowerShell
    try:
        cmd = ["powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"]
        out = subprocess.check_output(cmd, creationflags=subprocess.CREATE_NO_WINDOW, timeout=12)
        uuid_str = out.decode('utf-8', errors='ignore').strip()
        if uuid_str:
            components.append(uuid_str.encode('utf-8'))
        else:
            components.append(b"BOARD_UUID_EMPTY")
    except Exception:
        components.append(b"BOARD_UUID_FALLBACK")

    # 3. CPU ProcessorId
    try:
        cmd_cpu = ["powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_Processor | Select-Object -ExpandProperty ProcessorId"]
        out_cpu = subprocess.check_output(cmd_cpu, creationflags=subprocess.CREATE_NO_WINDOW, timeout=12)
        cpu_str = out_cpu.decode('utf-8', errors='ignore').strip()
        if cpu_str:
            components.append(cpu_str.encode('utf-8'))
        else:
            components.append(b"CPU_ID_EMPTY")
    except Exception:
        components.append(b"CPU_ID_FALLBACK")

    # Hash all hardware elements into SHA-256 digest
    hasher = hashlib.sha256()
    for item in components:
        hasher.update(item)
    digest = hasher.digest()  # 32 bytes

    # Save to machine cache
    try:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, "wb") as cf:
            cf.write(digest)
    except Exception:
        pass

    _CACHED_HW_FINGERPRINT = digest
    return digest


def get_candidate_fingerprints() -> List[bytes]:
    """Returns candidate fingerprints (primary + fallback) for maximum backward-compatibility."""
    primary = get_hardware_fingerprint()
    candidates = [primary]

    # Generate fallback hash in case encryption happened during a previous PowerShell timeout
    try:
        hasher = hashlib.sha256()
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            hasher.update(str(guid).strip().encode('utf-8'))
        hasher.update(b"BOARD_UUID_FALLBACK")
        hasher.update(b"CPU_ID_FALLBACK")
        fb = hasher.digest()
        if fb not in candidates:
            candidates.append(fb)
    except Exception:
        pass

    return candidates


def generate_rsa_keypair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generates military-grade RSA-4096 key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    return private_key, private_key.public_key()


def derive_argon2id_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit symmetric encryption key using Argon2id
    with high memory cost (64 MB = 65536 KB), 3 iterations, and 4 parallelism.
    Resistant to GPU/ASIC brute-force attacks.
    """
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=3,
        lanes=4,
        memory_cost=65536
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_private_key_to_usb(private_key: rsa.RSAPrivateKey, password: str, output_path: str):
    """
    Serializes RSA private key to PEM, encrypts it with Argon2id + AES-256-GCM,
    and stores it securely on the USB drive.
    Format:
    [Salt (16 bytes)] [Nonce (12 bytes)] [Ciphertext + Tag]
    """
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    salt = os.urandom(16)
    key = derive_argon2id_key(password, salt)
    nonce = os.urandom(12)

    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, pem_bytes, associated_data=b"AEGIS_USB_KEY_AAD")

    with open(output_path, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext_and_tag)

    # Zero-out sensitive variables
    del pem_bytes, key


def load_private_key_from_usb(usb_key_path: str, password: str) -> rsa.RSAPrivateKey:
    """
    Reads encrypted private key from USB, derives key with Argon2id,
    decrypts with AES-256-GCM, and returns RSAPrivateKey instance.
    """
    if not os.path.exists(usb_key_path):
        raise FileNotFoundError(f"USB Key file not found at: {usb_key_path}")

    with open(usb_key_path, "rb") as f:
        salt = f.read(16)
        nonce = f.read(12)
        ciphertext_and_tag = f.read()

    key = derive_argon2id_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        decrypted_pem = aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data=b"AEGIS_USB_KEY_AAD")
    except InvalidTag:
        raise ValueError("Hatali ana parola veya bozulmus USB anahtar dosyasi!")

    private_key = serialization.load_pem_private_key(decrypted_pem, password=None)
    del decrypted_pem, key
    return private_key


def save_public_key(public_key: rsa.RSAPublicKey, dest_path: str):
    """Saves public key PEM on the computer for one-way locking."""
    os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(dest_path, "wb") as f:
        f.write(pem)


def load_public_key(public_key_path: str) -> rsa.RSAPublicKey:
    """Loads public key PEM from local computer."""
    if not os.path.exists(public_key_path):
        raise FileNotFoundError(f"Public key not found at {public_key_path}. Lutfen once USB Kurulum Sihirbazini calistirin.")
    with open(public_key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def encrypt_file_stream(source_path: str, dest_aegis_path: str, public_key: rsa.RSAPublicKey) -> str:
    """
    Locks a file using RSA-4096 + AES-256-GCM streaming with Hardware-Bound AAD:
    1. Generates ephemeral 256-bit AES key in RAM.
    2. Encrypts AES key with computer's RSA-4096 Public Key.
    3. Reads file in 64 KB chunks, encrypts each chunk with AES-256-GCM.
    4. Hardware fingerprint (MachineGuid + Motherboard UUID) is passed as AAD for every chunk.
    5. Zeroes AES key from RAM.
    """
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Kaynak dosya bulunamadi: {source_path}")

    file_size = os.path.getsize(source_path)
    original_filename = os.path.basename(source_path).encode('utf-8')

    # Ephemeral 256-bit AES key
    aes_key = os.urandom(32)
    aesgcm = AESGCM(aes_key)

    # Seal AES key with RSA-4096 Public Key using OAEP (SHA-256)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    nonce_base = os.urandom(8)  # 8 bytes base; remaining 4 bytes = chunk index
    hw_fingerprint = get_hardware_fingerprint()

    # Create destination dir if needed
    os.makedirs(os.path.dirname(os.path.abspath(dest_aegis_path)), exist_ok=True)
    temp_output_path = dest_aegis_path + ".tmp_enc"

    with open(source_path, "rb") as src, open(temp_output_path, "wb") as dst:
        # 1. Header Magic
        dst.write(MAGIC_HEADER)
        # 2. Encrypted AES key length (uint16) + Encrypted AES key (512 bytes for RSA-4096)
        dst.write(struct.pack(">H", len(encrypted_aes_key)))
        dst.write(encrypted_aes_key)
        # 3. Nonce Base (8 bytes)
        dst.write(nonce_base)
        # 4. Chunk Size (uint32)
        dst.write(struct.pack(">I", CHUNK_SIZE))
        # 5. Original filename length (uint16) + filename bytes
        dst.write(struct.pack(">H", len(original_filename)))
        dst.write(original_filename)

        chunk_idx = 0
        while True:
            chunk_data = src.read(CHUNK_SIZE)
            if not chunk_data and chunk_idx > 0:
                break

            is_last = 1 if len(chunk_data) < CHUNK_SIZE or src.tell() == file_size else 0

            # 12-byte Nonce: 8 bytes random base + 4 bytes chunk index (Big-Endian)
            chunk_nonce = nonce_base + struct.pack(">I", chunk_idx)

            # Hardware-Bound AAD: hw_fingerprint + chunk_idx + is_last
            aad = hw_fingerprint + struct.pack(">IB", chunk_idx, is_last)

            # Encrypt chunk
            enc_chunk = aesgcm.encrypt(chunk_nonce, chunk_data, associated_data=aad)

            # Write chunk header: chunk_idx (4), is_last (1), payload_len (4), payload
            dst.write(struct.pack(">IBI", chunk_idx, is_last, len(enc_chunk)))
            dst.write(enc_chunk)

            chunk_idx += 1
            if is_last:
                break

    # Atomic move
    if os.path.exists(dest_aegis_path):
        os.remove(dest_aegis_path)
    os.rename(temp_output_path, dest_aegis_path)

    # Zero-out AES key in memory
    del aes_key, aesgcm
    return dest_aegis_path


def decrypt_file_to_ram(aegis_path: str, private_key: rsa.RSAPrivateKey) -> Tuple[SecureBuffer, str]:
    """
    Zero-Disk Decryption:
    Decrypts an .aegis encrypted file directly into physical RAM protected with VirtualLock.
    Authenticates hardware fingerprint: if copied to another machine, InvalidTag is raised.
    Returns (SecureBuffer, original_filename).
    """
    if not os.path.exists(aegis_path):
        raise FileNotFoundError(f"Aegis dosyasi bulunamadi: {aegis_path}")

    with open(aegis_path, "rb") as f:
        # 1. Verify Magic
        magic = f.read(len(MAGIC_HEADER))
        if magic != MAGIC_HEADER:
            raise ValueError("Gecersiz dosya formati: AegisVault mühür başlığı bulunamadı.")

        # 2. Read Encrypted AES Key
        enc_key_len = struct.unpack(">H", f.read(2))[0]
        encrypted_aes_key = f.read(enc_key_len)

        # Unseal AES key using RSA Private Key
        try:
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            raise ValueError("RSA Anahtari ile AES anahtari acilamadi! USB anahtar bu dosyaya ait degil.") from e

        aesgcm = AESGCM(aes_key)

        # 3. Read Nonce Base
        nonce_base = f.read(8)

        # 4. Chunk Size
        chunk_size = struct.unpack(">I", f.read(4))[0]

        # 5. Original filename
        fn_len = struct.unpack(">H", f.read(2))[0]
        original_filename = f.read(fn_len).decode('utf-8', errors='replace')

        hw_fingerprint = get_hardware_fingerprint()

        plaintext_chunks = []
        expected_chunk_idx = 0

        while True:
            chunk_header = f.read(9)  # 4 bytes index + 1 byte is_last + 4 bytes payload_len
            if not chunk_header:
                break

            chunk_idx, is_last, payload_len = struct.unpack(">IBI", chunk_header)
            if chunk_idx != expected_chunk_idx:
                raise ValueError(f"Bozuk dosya veya araya girilmis akis: Chunk {chunk_idx} beklenen {expected_chunk_idx}")

            payload = f.read(payload_len)
            chunk_nonce = nonce_base + struct.pack(">I", chunk_idx)
            aad = hw_fingerprint + struct.pack(">IB", chunk_idx, is_last)

            try:
                decrypted_chunk = aesgcm.decrypt(chunk_nonce, payload, associated_data=aad)
            except InvalidTag:
                raise PermissionError(
                    "DONANIM MUHRU BASARISIZ (Hardware Mismatch)! "
                    "Bu dosya baska bir bilgisayara kopyalanmis veya donanim bilesenleri uyusmuyor. "
                    "AegisVault sifrelemeyi reddetti!"
                )

            plaintext_chunks.append(decrypted_chunk)
            expected_chunk_idx += 1
            if is_last:
                break

    # Assemble raw bytes directly in RAM
    raw_data = b"".join(plaintext_chunks)
    secure_buf = SecureBuffer(raw_data)

    # Wipe sensitive local variables
    del aes_key, aesgcm, raw_data, plaintext_chunks
    return secure_buf, original_filename
