# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import hashlib
from sympy import mod_inverse
import math
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def multiplicative_encrypt(plaintext, key):
    """Multiplicative cipher encryption"""
    if math.gcd(key, 26) != 1:
        raise ValueError("Key must be coprime with 26")

    result = ""
    for char in plaintext.upper():
        if char.isalpha():
            encrypted = ((ord(char) - ord('A')) * key) % 26
            result += chr(encrypted + ord('A'))
        else:
            result += char
    return result

def rsa_generate_keys(key_size=2048):
    """Generate RSA key pair"""
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key_pem):
    """RSA encryption"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext)

def rsa_decrypt(ciphertext, private_key_pem):
    """RSA decryption"""
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)

def sha256(data):
    """SHA-256 hashing"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()

def multiplicative_decrypt(ciphertext, key):
    """Multiplicative cipher decryption"""
    if math.gcd(key, 26) != 1:
        raise ValueError("Key must be coprime with 26")

    key_inv = mod_inverse(key, 26)
    result = ""
    for char in ciphertext.upper():
        if char.isalpha():
            decrypted = ((ord(char) - ord('A')) * key_inv) % 26
            result += chr(decrypted + ord('A'))
        else:
            result += char
    return result

k = 25
msg = "DANCING"
bob_private_key, bob_public_key  = rsa_generate_keys()

enc_msg = multiplicative_encrypt(msg, k)
enc_k = rsa_encrypt(str(k), bob_public_key)

dec_k = rsa_decrypt(enc_k, bob_private_key)
dec_msg = multiplicative_decrypt(enc_msg, int(dec_k))

print("Message:", msg)
print("Encrypted Message to Bob:",enc_msg )
print("Encrypted Key to Bob:", enc_k)
print("\nDecrypted Key at Bob:", dec_k)
print("Decrypted Message at Bob:", dec_msg)

h1 = sha256(dec_msg)
h2 = sha256(msg)
print("\nHash Integrity: ", h1 == h2)
print(h1)
print(h2)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
