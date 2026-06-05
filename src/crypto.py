"""
ABAVANDIMWE Advanced Cryptography Engine
Author: Mugisha Pc
AES-256-GCM with Argon2id Key Derivation
"""

import secrets
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives import hashes
from argon2 import PasswordHasher
from argon2 import Type

class CryptoEngine:
    SALT_LENGTH = 32
    NONCE_LENGTH = 12
    
    def __init__(self):
        self.argon2 = PasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=2,
            type=Type.ID
        )
    
    def generate_salt(self) -> str:
        return base64.b64encode(secrets.token_bytes(self.SALT_LENGTH)).decode()
    
    def _derive_key(self, password: str, salt: str) -> bytes:
        salt_bytes = salt.encode()
        argon_hash = self.argon2.hash(f"{password}:{salt}")
        kdf = PBKDF2(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
        )
        return kdf.derive(argon_hash.encode())
    
    def encrypt(self, plaintext: str, password: str, salt: str) -> str:
        key = self._derive_key(password, salt)
        nonce = secrets.token_bytes(self.NONCE_LENGTH)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        combined = nonce + ciphertext
        return base64.b64encode(combined).decode()
    
    def decrypt(self, encrypted: str, password: str, salt: str) -> str:
        key = self._derive_key(password, salt)
        combined = base64.b64decode(encrypted)
        nonce = combined[:self.NONCE_LENGTH]
        ciphertext = combined[self.NONCE_LENGTH:]
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted.decode()

crypto = CryptoEngine()
