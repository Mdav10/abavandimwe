"""
ABAVANDIMWE Cryptography Engine
Author: Mugisha Pc
"""

import secrets
import base64
import hashlib

class CryptoEngine:
    @staticmethod
    def generate_salt() -> str:
        return base64.b64encode(secrets.token_bytes(32)).decode()
    
    @staticmethod
    def _derive_key(password: str, salt: str) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, 32)
    
    @staticmethod
    def encrypt(plaintext: str, password: str, salt: str) -> str:
        key = CryptoEngine._derive_key(password, salt)
        plaintext_bytes = plaintext.encode()
        ciphertext = bytearray()
        for i in range(len(plaintext_bytes)):
            ciphertext.append(plaintext_bytes[i] ^ key[i % len(key)])
        nonce = secrets.token_bytes(8)
        result = nonce + ciphertext
        return base64.b64encode(result).decode()
    
    @staticmethod
    def decrypt(encrypted: str, password: str, salt: str) -> str:
        key = CryptoEngine._derive_key(password, salt)
        data = base64.b64decode(encrypted)
        ciphertext = data[8:]
        plaintext_bytes = bytearray()
        for i in range(len(ciphertext)):
            plaintext_bytes.append(ciphertext[i] ^ key[i % len(key)])
        return plaintext_bytes.decode()

crypto = CryptoEngine()
