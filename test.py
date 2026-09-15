"""
EduSecure - Secure Education Data Management System
ICT 3141 - Information Security Lab

Implements:
  - DES symmetric encryption (student uploads records encrypted with DES)
  - RSA digital signatures (student signs hash, faculty/HoD verify)
  - SHA-256 hashing (integrity check)
  - Role-based menu: Student, Faculty, HoD
"""

"""
import hashlib
import socket
from datetime import datetime

from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
"""

import hashlib
import datetime
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# ---------------------------------------------------------------------------
# GLOBAL "DATABASE" - in-memory dict acting as our file/record store
# ---------------------------------------------------------------------------
records = {}
# each entry looks like:
# records[filename] = {
#     "encrypted": bytes,          # DES ciphertext
#     "hash": str,                 # SHA-256 hex digest of the encrypted record
#     "signature": bytes,          # RSA signature of the hash
#     "upload_time": str,
#     "verification": {            # filled in once Faculty verifies
#         "decrypted_ok": bool,
#         "signature_valid": bool,
#         "hash_matches": bool,
#         "verified_time": str
#     }
# }


# ---------------------------------------------------------------------------
# CRYPTO HELPER FUNCTIONS (these are the "given" building blocks)
# ---------------------------------------------------------------------------

def des_encrypt(plaintext: str, key: bytes) -> bytes:
    """Encrypt plaintext using DES (ECB mode) with PKCS7 padding."""
    cipher = DES.new(key, DES.MODE_ECB)
    padded = pad(plaintext.encode(), DES.block_size)
    return cipher.encrypt(padded)


def des_decrypt(ciphertext: bytes, key: bytes) -> str:
    """Decrypt DES ciphertext (ECB mode) and remove PKCS7 padding."""
    cipher = DES.new(key, DES.MODE_ECB)
    padded = cipher.decrypt(ciphertext)
    return unpad(padded, DES.block_size).decode()


def sha256_hash(data: bytes) -> str:
    """Return SHA-256 hex digest of the given bytes."""
    return hashlib.sha256(data).hexdigest()


def rsa_sign(hash_hex: str, private_key: RSA.RsaKey) -> bytes:
    """Sign a hex-digest hash string using an RSA private key."""
    h = SHA256.new(hash_hex.encode())
    return pkcs1_15.new(private_key).sign(h)


def rsa_verify(hash_hex: str, signature: bytes, public_key: RSA.RsaKey) -> bool:
    """Verify an RSA signature against the given hex-digest hash string."""
    h = SHA256.new(hash_hex.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def get_timestamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# ROLE CLASSES - each exposes only the operations that role is allowed to do
# ---------------------------------------------------------------------------

class Student:
    def __init__(self, name, des_key, rsa_private_key):
        self.name = name
        self.des_key = des_key
        self.private_key = rsa_private_key

    def upload_record(self, filename: str, plaintext: str):
        """Encrypt with DES, hash the ciphertext, sign the hash with RSA."""
        encrypted = des_encrypt(plaintext, self.des_key)
        hash_val = sha256_hash(encrypted)
        signature = rsa_sign(hash_val, self.private_key)

        records[filename] = {
            "encrypted": encrypted,
            "hash": hash_val,
            "signature": signature,
            "upload_time": get_timestamp(),
            "verification": None
        }
        print(f"\n[Student:{self.name}] Uploaded '{filename}' successfully.")
        print(f"  Encrypted (hex): {encrypted.hex()}")
        print(f"  SHA-256 hash   : {hash_val}")
        print(f"  Signature (hex): {signature.hex()[:32]}...")

    def view_my_records(self):
        if not records:
            print("\nNo records uploaded yet.")
            return
        print(f"\n--- Records uploaded ---")
        for fname, rec in records.items():
            print(f"\nFile      : {fname}")
            print(f"Encrypted : {rec['encrypted'].hex()}")
            print(f"Hash      : {rec['hash']}")
            print(f"Signature : {rec['signature'].hex()[:32]}...")
            print(f"Uploaded  : {rec['upload_time']}")


class Faculty:
    def __init__(self, des_key, rsa_public_key):
        self.des_key = des_key
        self.public_key = rsa_public_key

    def decrypt_and_verify(self, filename: str):
        """Decrypt with DES, verify RSA signature, recompute hash and compare."""
        if filename not in records:
            print(f"\nNo such record: {filename}")
            return
        rec = records[filename]

        # 1. Decrypt
        try:
            decrypted = des_decrypt(rec["encrypted"], self.des_key)
            decrypted_ok = True
        except Exception as e:
            decrypted = None
            decrypted_ok = False

        # 2. Verify RSA signature on the stored hash
        signature_valid = rsa_verify(rec["hash"], rec["signature"], self.public_key)

        # 3. Recompute SHA-256 over the encrypted record, compare to stored hash
        recomputed_hash = sha256_hash(rec["encrypted"])
        hash_matches = (recomputed_hash == rec["hash"])

        # 4. Store verification result with timestamp
        rec["verification"] = {
            "decrypted_ok": decrypted_ok,
            "signature_valid": signature_valid,
            "hash_matches": hash_matches,
            "verified_time": get_timestamp()
        }

        print(f"\n[Faculty] Verification for '{filename}':")
        print(f"  Decrypted record  : {decrypted}")
        print(f"  Signature valid   : {signature_valid}")
        print(f"  Hash matches      : {hash_matches}")
        print(f"  Overall authentic : {decrypted_ok and signature_valid and hash_matches}")


class HoD:
    def __init__(self, rsa_public_key):
        self.public_key = rsa_public_key

    def view_hash(self, filename: str):
        if filename not in records:
            print(f"\nNo such record: {filename}")
            return
        rec = records[filename]
        print(f"\n[HoD] Record '{filename}':")
        print(f"  Hash      : {rec['hash']}")
        print(f"  Uploaded  : {rec['upload_time']}")

    def verify_signature(self, filename: str):
        if filename not in records:
            print(f"\nNo such record: {filename}")
            return
        rec = records[filename]
        valid = rsa_verify(rec["hash"], rec["signature"], self.public_key)
        print(f"\n[HoD] Signature check for '{filename}': "
              f"{'VALID' if valid else 'INVALID'}")


# ---------------------------------------------------------------------------
# SETUP - generate keys once, shared between roles
# ---------------------------------------------------------------------------

def setup():
    des_key = b"8bytekey"          # DES key MUST be exactly 8 bytes
    rsa_key = RSA.generate(2048)   # student's RSA key pair
    private_key = rsa_key
    public_key = rsa_key.publickey()

    student = Student("Harshith", des_key, private_key)
    faculty = Faculty(des_key, public_key)
    hod = HoD(public_key)
    return student, faculty, hod


# ---------------------------------------------------------------------------
# MENU-DRIVEN MAIN PROGRAM
# ---------------------------------------------------------------------------

def student_menu(student: Student):
    while True:
        print("\n--- Student Menu ---")
        print("1. Upload & sign a record")
        print("2. View my uploaded records")
        print("3. Back")
        choice = input("Choose: ").strip()

        if choice == "1":
            filename = input("Filename (e.g. ISL-5CCE-A2.txt): ").strip()
            content = input("Record content: ").strip()
            student.upload_record(filename, content)
        elif choice == "2":
            student.view_my_records()
        elif choice == "3":
            break
        else:
            print("Invalid choice.")


def faculty_menu(faculty: Faculty):
    while True:
        print("\n--- Faculty Menu ---")
        print("1. Decrypt & verify a record")
        print("2. Back")
        choice = input("Choose: ").strip()

        if choice == "1":
            filename = input("Filename to verify: ").strip()
            faculty.decrypt_and_verify(filename)
        elif choice == "2":
            break
        else:
            print("Invalid choice.")


def hod_menu(hod: HoD):
    while True:
        print("\n--- HoD Menu ---")
        print("1. View record hash")
        print("2. Verify record signature")
        print("3. Back")
        choice = input("Choose: ").strip()

        if choice == "1":
            filename = input("Filename: ").strip()
            hod.view_hash(filename)
        elif choice == "2":
            filename = input("Filename: ").strip()
            hod.verify_signature(filename)
        elif choice == "3":
            break
        else:
            print("Invalid choice.")


def main():
    student, faculty, hod = setup()

    while True:
        print("\n===== EduSecure - Main Menu =====")
        print("1. Student")
        print("2. Faculty")
        print("3. HoD")
        print("4. Exit")
        choice = input("Select role: ").strip()

        if choice == "1":
            student_menu(student)
        elif choice == "2":
            faculty_menu(faculty)
        elif choice == "3":
            hod_menu(hod)
        elif choice == "4":
            print("Exiting EduSecure. Goodbye.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
