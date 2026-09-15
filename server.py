# server.py - Server-side digital signature and hash verification

import socket
import json
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import random


class CryptoServer:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        """Start the server and listen for connections"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"[+] Server started on {self.host}:{self.port}")

        while True:
            client_socket, address = self.server_socket.accept()
            print(f"[+] Connection from {address}")
            self.handle_client(client_socket)

    def handle_client(self, client_socket):
        """Handle client requests"""
        try:
            while True:
                data = client_socket.recv(8192)
                if not data:
                    break
                request = json.loads(data.decode())
                response = self.process_request(request)
                client_socket.send(json.dumps(response).encode())
        except Exception as e:
            print(f"[-] Error: {e}")
        finally:
            client_socket.close()

    def process_request(self, request):
        """Process different types of verification requests"""
        req_type = request.get('type')

        if req_type == 'RSA':
            return self.verify_rsa(request)
        elif req_type == 'Rabin':
            return self.verify_rabin(request)
        elif req_type == 'DH':
            return self.perform_dh_key_exchange(request)
        elif req_type == 'ElGamal':
            return self.verify_elgamal(request)
        elif req_type == 'Schnorr':
            return self.verify_schnorr(request)
        elif req_type == 'HASH':
            return self.verify_hash(request)
        else:
            return {'status': 'error', 'message': 'Unknown request type'}

    def verify_rsa(self, request):
        """Verify RSA digital signature"""
        try:
            message = request['message'].encode()
            signature = bytes.fromhex(request['signature'])
            public_key_pem = request['public_key']

            public_key = RSA.import_key(public_key_pem)

            h = SHA256.new(message)
            try:
                pkcs1_15.new(public_key).verify(h, signature)
                return {'status': 'success', 'verified': True, 'message': 'RSA signature is valid'}
            except (ValueError, TypeError):
                return {'status': 'success', 'verified': False, 'message': 'RSA signature is invalid'}
        except Exception as e:
            return {'status': 'error', 'message': f'RSA verification error: {str(e)}'}

    def verify_rabin(self, request):
        """Verify Rabin signature"""
        try:
            message = request['message']
            signature = request['signature']
            n = request['n']

            # Rabin signature verification: s^2 mod n = H(m) mod n
            message_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16) % n
            computed_hash = (signature * signature) % n

            is_valid = (computed_hash == message_hash)
            return {
                'status': 'success',
                'verified': is_valid,
                'message': f'Rabin signature is {"valid" if is_valid else "invalid"}'
            }
        except Exception as e:
            return {'status': 'error', 'message': f'Rabin verification error: {str(e)}'}

    def perform_dh_key_exchange(self, request):
        """Perform Diffie-Hellman key exchange (server side)"""
        try:
            client_public = request['client_public']
            p = request['p']
            g = request['g']

            server_private = random.randint(2, p - 2)
            server_public = pow(g, server_private, p)
            shared_secret = pow(client_public, server_private, p)

            return {
                'status': 'success',
                'server_public': server_public,
                'shared_secret': shared_secret,
                'message': 'DH key exchange completed'
            }
        except Exception as e:
            return {'status': 'error', 'message': f'DH key exchange error: {str(e)}'}

    def verify_elgamal(self, request):
        """Verify ElGamal signature"""
        try:
            message = request['message']
            r = request['r']
            s = request['s']
            p = request['p']
            g = request['g']
            y = request['y']

            message_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16) % (p - 1)
            left_side = pow(g, message_hash, p)
            right_side = (pow(y, r, p) * pow(r, s, p)) % p

            is_valid = (left_side == right_side)
            return {
                'status': 'success',
                'verified': is_valid,
                'message': f'ElGamal signature is {"valid" if is_valid else "invalid"}'
            }
        except Exception as e:
            return {'status': 'error', 'message': f'ElGamal verification error: {str(e)}'}

    def verify_schnorr(self, request):
        """Verify Schnorr signature"""
        try:
            message = request['message']
            r = request['r']
            s = request['s']
            p = request['p']
            q = request['q']
            g = request['g']
            y = request['y']

            e = int(hashlib.sha256((message + str(r)).encode()).hexdigest(), 16) % q
            computed_r = (pow(g, s, p) * pow(y, e, p)) % p

            is_valid = (computed_r == r)
            return {
                'status': 'success',
                'verified': is_valid,
                'message': f'Schnorr signature is {"valid" if is_valid else "invalid"}'
            }
        except Exception as e:
            return {'status': 'error', 'message': f'Schnorr verification error: {str(e)}'}

    def verify_hash(self, request):
        """Verify hash values"""
        try:
            message = request['message'].encode()
            hash_type = request['hash_type']
            provided_hash = request['hash_value']

            if hash_type == 'MD5':
                computed_hash = hashlib.md5(message).hexdigest()
            elif hash_type == 'SHA1':
                computed_hash = hashlib.sha1(message).hexdigest()
            elif hash_type == 'SHA256':
                computed_hash = hashlib.sha256(message).hexdigest()
            elif hash_type == 'SHA512':
                computed_hash = hashlib.sha512(message).hexdigest()
            else:
                return {'status': 'error', 'message': 'Unknown hash type'}

            is_valid = (computed_hash == provided_hash)
            return {
                'status': 'success',
                'verified': is_valid,
                'computed_hash': computed_hash,
                'message': f'{hash_type} hash is {"valid" if is_valid else "invalid"}'
            }
        except Exception as e:
            return {'status': 'error', 'message': f'Hash verification error: {str(e)}'}


if __name__ == "__main__":
    server = CryptoServer()
    server.start()
