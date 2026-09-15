# client_EvalPrep.py - Client-side key/signature generation, sent to server for verification

import socket
import json
import hashlib
import random
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


class CryptoClient:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port

    def send_request(self, request: dict) -> dict:
        """Open a connection, send one JSON request, get one JSON response."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        sock.send(json.dumps(request).encode())
        data = sock.recv(8192)
        sock.close()
        return json.loads(data.decode())

    # ------------------------------------------------------------------
    # RSA - sign locally, ask server to verify
    # ------------------------------------------------------------------
    def rsa_demo(self, message: str):
        key = RSA.generate(2048)
        private_key, public_key = key, key.publickey()

        h = SHA256.new(message.encode())
        signature = pkcs1_15.new(private_key).sign(h)

        request = {
            "type": "RSA",
            "message": message,
            "signature": signature.hex(),
            "public_key": public_key.export_key().decode()
        }
        return self.send_request(request)

    # ------------------------------------------------------------------
    # Rabin - real construction: p, q both == 3 (mod 4), so modular square
    # roots can be computed directly via x^((p+1)/4) mod p (and mod q),
    # then combined with CRT. Not every hash is a quadratic residue, so we
    # pad with a small counter until we find one that is (standard trick).
    # ------------------------------------------------------------------
    def rabin_demo(self, message: str):
        p, q = 499, 547        # both prime and both == 3 mod 4; n = p*q
        n = p * q

        counter = 0
        while True:
            padded = f"{message}|{counter}"
            h = int(hashlib.sha256(padded.encode()).hexdigest(), 16) % n
            if pow(h, (p - 1) // 2, p) == 1 and pow(h, (q - 1) // 2, q) == 1:
                message_hash = h
                break   # h is a quadratic residue mod both p and q
            counter += 1

        # square roots mod p and mod q
        mp = pow(message_hash, (p + 1) // 4, p)
        mq = pow(message_hash, (q + 1) // 4, q)

        # combine via CRT: find s such that s == mp (mod p), s == mq (mod q)
        q_inv = pow(q, -1, p)
        s = (mq + q * (q_inv * (mp - mq) % p)) % n

        request = {"type": "Rabin", "message": padded, "signature": s, "n": n}
        return self.send_request(request)

    # ------------------------------------------------------------------
    # Diffie-Hellman key exchange
    # ------------------------------------------------------------------
    def dh_demo(self):
        p = 23   # small prime for demo (use a large safe prime for real use)
        g = 5    # generator

        client_private = random.randint(2, p - 2)
        client_public = pow(g, client_private, p)

        request = {"type": "DH", "client_public": client_public, "p": p, "g": g}
        response = self.send_request(request)

        if response.get("status") == "success":
            server_public = response["server_public"]
            shared_secret_client_side = pow(server_public, client_private, p)
            response["shared_secret_client_side"] = shared_secret_client_side
            response["match"] = (shared_secret_client_side == response["shared_secret"])
        return response

    # ------------------------------------------------------------------
    # ElGamal signature: verification is g^H(m) mod p == (y^r * r^s) mod p
    # ------------------------------------------------------------------
    def elgamal_demo(self, message: str):
        p = 467          # small prime for demo
        g = 2            # generator
        x = random.randint(2, p - 2)          # private key
        y = pow(g, x, p)                      # public key

        while True:
            k = random.randint(2, p - 2)
            if self._gcd(k, p - 1) == 1:
                break

        message_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16) % (p - 1)
        r = pow(g, k, p)
        k_inv = pow(k, -1, p - 1)
        s = (k_inv * (message_hash - x * r)) % (p - 1)

        request = {"type": "ElGamal", "message": message, "r": r, "s": s,
                   "p": p, "g": g, "y": y}
        return self.send_request(request)

    @staticmethod
    def _gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    # ------------------------------------------------------------------
    # Schnorr signature: r = g^s * y^e mod p, where e = H(m || r)
    # ------------------------------------------------------------------
    def schnorr_demo(self, message: str):
        p = 467
        q = 233          # prime factor of p-1 (467-1 = 466 = 2*233)
        g = pow(4, (p - 1) // q, p)   # generator of order q

        x = random.randint(2, q - 1)     # private key
        y = pow(g, x, p)                 # public key

        k = random.randint(2, q - 1)
        r = pow(g, k, p)
        e = int(hashlib.sha256((message + str(r)).encode()).hexdigest(), 16) % q
        s = (k - x * e) % q

        request = {"type": "Schnorr", "message": message, "r": r, "s": s,
                   "p": p, "q": q, "g": g, "y": y}
        return self.send_request(request)

    # ------------------------------------------------------------------
    # Plain hash check
    # ------------------------------------------------------------------
    def hash_demo(self, message: str, hash_type: str = "SHA256"):
        hash_funcs = {
            "MD5": hashlib.md5,
            "SHA1": hashlib.sha1,
            "SHA256": hashlib.sha256,
            "SHA512": hashlib.sha512
        }
        digest = hash_funcs[hash_type](message.encode()).hexdigest()

        request = {"type": "HASH", "message": message,
                   "hash_type": hash_type, "hash_value": digest}
        return self.send_request(request)


def menu():
    client = CryptoClient()

    while True:
        print("\n===== Crypto Client - EvalPrep =====")
        print("1. RSA signature")
        print("2. Rabin signature")
        print("3. Diffie-Hellman key exchange")
        print("4. ElGamal signature")
        print("5. Schnorr signature")
        print("6. Hash check")
        print("7. Exit")
        choice = input("Choose: ").strip()

        if choice == "1":
            msg = input("Message: ")
            print(client.rsa_demo(msg))
        elif choice == "2":
            msg = input("Message: ")
            print(client.rabin_demo(msg))
        elif choice == "3":
            print(client.dh_demo())
        elif choice == "4":
            msg = input("Message: ")
            print(client.elgamal_demo(msg))
        elif choice == "5":
            msg = input("Message: ")
            print(client.schnorr_demo(msg))
        elif choice == "6":
            msg = input("Message: ")
            ht = input("Hash type (MD5/SHA1/SHA256/SHA512): ").strip().upper() or "SHA256"
            print(client.hash_demo(msg, ht))
        elif choice == "7":
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    menu()
