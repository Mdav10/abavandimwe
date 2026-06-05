"""
ABAVANDIMWE Cryptography Engine - Pure Python
Author: Mugisha Pc
"""

import secrets
import base64
import hashlib

class CryptoEngine:
    """Pure Python crypto - No Rust dependencies needed"""
    
    SALT_LENGTH = 32
    
    @staticmethod
    def generate_salt() -> str:
        return base64.b64encode(secrets.token_bytes(32)).decode()
    
    @staticmethod
    def _derive_key(password: str, salt: str) -> bytes:
        """PBKDF2 key derivation"""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt.encode(),
            100000,
            32
        )
    
    @staticmethod
    def encrypt(plaintext: str, password: str, salt: str) -> str:
        """Simple XOR encryption with derived key"""
        key = CryptoEngine._derive_key(password, salt)
        plaintext_bytes = plaintext.encode()
        
        # XOR encryption
        ciphertext = bytearray()
        for i in range(len(plaintext_bytes)):
            ciphertext.append(plaintext_bytes[i] ^ key[i % len(key)])
        
        # Add random nonce (8 bytes)
        nonce = secrets.token_bytes(8)
        result = nonce + ciphertext
        
        return base64.b64encode(result).decode()
    
    @staticmethod
    def decrypt(encrypted: str, password: str, salt: str) -> str:
        """XOR decryption"""
        key = CryptoEngine._derive_key(password, salt)
        data = base64.b64decode(encrypted)
        
        # Skip nonce (first 8 bytes)
        ciphertext = data[8:]
        
        # XOR decryption
        plaintext_bytes = bytearray()
        for i in range(len(ciphertext)):
            plaintext_bytes.append(ciphertext[i] ^ key[i % len(key)])
        
        return plaintext_bytes.decode()

crypto = CryptoEngine()
