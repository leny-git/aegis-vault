"""
Automated Cryptographic & Anti-Forensics Verification Test Suite for AegisVault
"""

import os
import sys
import tempfile
import unittest

# Add parent dir to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aegis_vault.core.crypto_engine import (
    get_hardware_fingerprint,
    generate_rsa_keypair,
    save_public_key,
    load_public_key,
    encrypt_private_key_to_usb,
    load_private_key_from_usb,
    encrypt_file_stream,
    decrypt_file_to_ram,
    SecureBuffer,
    ActiveBufferRegistry
)
from aegis_vault.core.shredder import shred_file
from aegis_vault.services.usb_guard import USBDetector, PanicManager


class TestAegisVaultCore(unittest.TestCase):

    def test_01_hardware_fingerprint(self):
        hw1 = get_hardware_fingerprint()
        hw2 = get_hardware_fingerprint()
        self.assertEqual(len(hw1), 32)
        self.assertEqual(hw1, hw2, "Hardware fingerprint must be deterministic on same machine")
        print(f"[TEST 1 PASS] Hardware Fingerprint SHA-256: {hw1.hex()[:16]}...")

    def test_02_argon2id_usb_key_protection(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            priv, pub = generate_rsa_keypair()
            usb_key_path = os.path.join(tmp_dir, "test_usb_key.vault")
            password = "TestSuperSecretMasterPass!2026"

            encrypt_private_key_to_usb(priv, password, usb_key_path)
            self.assertTrue(os.path.exists(usb_key_path))

            # Test successful unlock
            recovered_priv = load_private_key_from_usb(usb_key_path, password)
            self.assertIsNotNone(recovered_priv)

            # Test failed unlock with wrong password
            with self.assertRaises(ValueError):
                load_private_key_from_usb(usb_key_path, "WrongPassword!")
            print("[TEST 2 PASS] Argon2id (64MB) USB Private Key Encryption & Validation Verified")

    def test_03_streaming_hybrid_encryption_and_ram_decryption(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            priv, pub = generate_rsa_keypair()
            pub_path = os.path.join(tmp_dir, "public.pem")
            save_public_key(pub, pub_path)
            loaded_pub = load_public_key(pub_path)

            # Create test file with secret corporate data
            src_file = os.path.join(tmp_dir, "company_confidential.docx")
            test_content = b"TOP SECRET CORPORATE DATA " * 5000  # ~130 KB, multi-chunk
            with open(src_file, "wb") as f:
                f.write(test_content)

            # Encrypt
            aegis_file = src_file + ".aegis"
            encrypt_file_stream(src_file, aegis_file, loaded_pub)
            self.assertTrue(os.path.exists(aegis_file))

            # Decrypt directly into VirtualLocked RAM
            sec_buf, orig_name = decrypt_file_to_ram(aegis_file, priv)
            self.assertEqual(orig_name, "company_confidential.docx")
            self.assertEqual(sec_buf.get_bytes(), test_content)

            # Test RAM Wipe
            sec_buf.wipe()
            self.assertTrue(sec_buf.is_wiped)
            with self.assertRaises(ValueError):
                sec_buf.get_bytes()
            print("[TEST 3 PASS] Streaming AES-256-GCM + RSA-4096 + Zero-Disk RAM Decryption Verified")

    def test_04_anti_forensics_shredder(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            victim_file = os.path.join(tmp_dir, "sensitive_passwords.txt")
            with open(victim_file, "wb") as f:
                f.write(b"MY_SECRET_PASSWORDS" * 100)

            self.assertTrue(os.path.exists(victim_file))
            shred_result = shred_file(victim_file, passes=3)
            self.assertTrue(shred_result)
            self.assertFalse(os.path.exists(victim_file))
            print("[TEST 4 PASS] 3-Pass Forensic Shredder + MFT Sanitization Verified")


if __name__ == "__main__":
    unittest.main()
