#!/usr/bin/env python3
"""
Cryptography module for IronStack.
Provides encryption, decryption, hashing, signing, and key management.
Integrates with PyCryptodome for advanced cryptographic operations.
"""

import os
import json
import base64
import hashlib
import hmac
import secrets
import struct
import zlib
from pathlib import Path
from typing import Dict, Any, Optional, Union, Tuple
from datetime import datetime, timedelta

from ..logging_config import get_logger
from ..exceptions import (
    IronStackError,
    ValidationError,
    ConfigurationError,
)

logger = get_logger(__name__)

# Try to import PyCryptodome for advanced features
try:
    from Crypto.Cipher import AES
    from Crypto.Cipher import ChaCha20
    from Crypto.Cipher import Salsa20
    from Crypto.PublicKey import RSA
    from Crypto.PublicKey import ECC
    from Crypto.Hash import SHA256, SHA512, SHA3_256, SHA3_512
    from Crypto.Signature import pkcs1_15, eddsa
    from Crypto.Protocol.KDF import PBKDF2, scrypt
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
    logger.info("PyCryptodome loaded successfully")
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("PyCryptodome not available. Using built-in hashlib only.")


# ==========================================
# Constants
# ==========================================

DEFAULT_HASH_ALGORITHM = "sha256"
DEFAULT_ENCRYPTION_ALGORITHM = "AES-256-GCM"
DEFAULT_KEY_SIZE = 256  # bits
DEFAULT_SALT_SIZE = 32  # bytes
DEFAULT_ITERATIONS = 100_000
DEFAULT_SIGNING_ALGORITHM = "HMAC-SHA256"

PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128

# ==========================================
# Utility Functions
# ==========================================

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time to prevent timing attacks."""
    return hmac.compare_digest(a, b)


def generate_salt(size: int = DEFAULT_SALT_SIZE) -> bytes:
    """Generate a cryptographically secure random salt."""
    if CRYPTO_AVAILABLE:
        return get_random_bytes(size)
    return os.urandom(size)


def generate_key(size: int = DEFAULT_KEY_SIZE // 8) -> bytes:
    """Generate a cryptographically secure random key."""
    if CRYPTO_AVAILABLE:
        return get_random_bytes(size)
    return os.urandom(size)


def generate_nonce(size: int = 12) -> bytes:
    """Generate a random nonce/IV."""
    if CRYPTO_AVAILABLE:
        return get_random_bytes(size)
    return os.urandom(size)


# ==========================================
# Password Hashing
# ==========================================

class PasswordHasher:
    """
    Secure password hashing using PBKDF2, scrypt, or Argon2.
    """
    
    @staticmethod
    def hash_password(
        password: str,
        algorithm: str = "pbkdf2_sha256",
        salt: Optional[bytes] = None,
        iterations: int = DEFAULT_ITERATIONS,
    ) -> Dict[str, Any]:
        """
        Hash a password securely.
        
        Args:
            password: Plain text password
            algorithm: Hashing algorithm (pbkdf2_sha256, scrypt, argon2)
            salt: Optional salt (generated if None)
            iterations: Number of iterations for PBKDF2
            
        Returns:
            Dictionary with hash, salt, algorithm, iterations
        """
        if not password:
            raise ValidationError("Password cannot be empty", field="password")
        
        if len(password) < PASSWORD_MIN_LENGTH:
            raise ValidationError(
                f"Password must be at least {PASSWORD_MIN_LENGTH} characters",
                field="password",
            )
        
        if len(password) > PASSWORD_MAX_LENGTH:
            raise ValidationError(
                f"Password must be at most {PASSWORD_MAX_LENGTH} characters",
                field="password",
            )
        
        salt = salt or generate_salt()
        password_bytes = password.encode('utf-8')
        
        if algorithm == "pbkdf2_sha256":
            if CRYPTO_AVAILABLE:
                key = PBKDF2(password_bytes, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
            else:
                key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, iterations, dklen=32)
        
        elif algorithm == "pbkdf2_sha512":
            if CRYPTO_AVAILABLE:
                key = PBKDF2(password_bytes, salt, dkLen=64, count=iterations, hmac_hash_module=SHA512)
            else:
                key = hashlib.pbkdf2_hmac('sha512', password_bytes, salt, iterations, dklen=64)
        
        elif algorithm == "scrypt":
            if CRYPTO_AVAILABLE:
                key = scrypt(password_bytes, salt, key_len=32, N=16384, r=8, p=1)
            else:
                key = hashlib.scrypt(password_bytes, salt=salt, n=16384, r=8, p=1, dklen=32)
        
        else:
            raise ValidationError(f"Unsupported algorithm: {algorithm}", field="algorithm")
        
        return {
            "hash": base64.b64encode(key).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8'),
            "algorithm": algorithm,
            "iterations": iterations,
        }
    
    @staticmethod
    def verify_password(
        password: str,
        stored_hash: str,
        stored_salt: str,
        algorithm: str = "pbkdf2_sha256",
        iterations: int = DEFAULT_ITERATIONS,
    ) -> bool:
        """
        Verify a password against stored hash.
        
        Args:
            password: Plain text password to verify
            stored_hash: Base64 encoded stored hash
            stored_salt: Base64 encoded stored salt
            algorithm: Algorithm used for hashing
            iterations: Number of iterations used
            
        Returns:
            True if password matches
        """
        try:
            salt = base64.b64decode(stored_salt)
            expected_hash = base64.b64decode(stored_hash)
            
            result = PasswordHasher.hash_password(
                password=password,
                algorithm=algorithm,
                salt=salt,
                iterations=iterations,
            )
            
            actual_hash = base64.b64decode(result["hash"])
            return constant_time_compare(actual_hash, expected_hash)
        except Exception:
            return False
    
    @staticmethod
    def check_password_strength(password: str) -> Dict[str, Any]:
        """
        Check password strength and return a score.
        
        Args:
            password: Password to check
            
        Returns:
            Dictionary with strength score and feedback
        """
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 3
        elif len(password) >= 10:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Password is too short (minimum 8 characters)")
        
        # Complexity checks
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/~`" for c in password):
            score += 2
        else:
            feedback.append("Add special characters")
        
        # Determine strength
        if score >= 7:
            strength = "very_strong"
        elif score >= 5:
            strength = "strong"
        elif score >= 3:
            strength = "moderate"
        else:
            strength = "weak"
        
        return {
            "score": score,
            "max_score": 8,
            "strength": strength,
            "feedback": feedback if feedback else ["Password is strong!"],
        }


# ==========================================
# Symmetric Encryption
# ==========================================

class SymmetricEncryption:
    """
    Symmetric encryption using AES-GCM or ChaCha20.
    """
    
    def __init__(
        self,
        algorithm: str = DEFAULT_ENCRYPTION_ALGORITHM,
        key: Optional[bytes] = None,
        key_size: int = DEFAULT_KEY_SIZE // 8,
    ):
        """
        Initialize symmetric encryption.
        
        Args:
            algorithm: Encryption algorithm
            key: Encryption key (generated if None)
            key_size: Key size in bytes
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("PyCryptodome is required for encryption. Install with: pip install pycryptodome")
        
        self.algorithm = algorithm
        self.key = key or generate_key(key_size)
        self.key_size = len(self.key)
    
    def encrypt(self, plaintext: Union[str, bytes]) -> Dict[str, str]:
        """
        Encrypt data.
        
        Args:
            plaintext: Data to encrypt (string or bytes)
            
        Returns:
            Dictionary with ciphertext, nonce, tag (all base64 encoded)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        if "AES" in self.algorithm.upper():
            return self._encrypt_aes_gcm(plaintext)
        elif "CHACHA" in self.algorithm.upper():
            return self._encrypt_chacha20(plaintext)
        elif "SALSA" in self.algorithm.upper():
            return self._encrypt_salsa20(plaintext)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {self.algorithm}")
    
    def decrypt(self, ciphertext: str, nonce: str, tag: Optional[str] = None) -> bytes:
        """
        Decrypt data.
        
        Args:
            ciphertext: Base64 encoded ciphertext
            nonce: Base64 encoded nonce
            tag: Base64 encoded authentication tag (for GCM mode)
            
        Returns:
            Decrypted bytes
        """
        ciphertext_bytes = base64.b64decode(ciphertext)
        nonce_bytes = base64.b64decode(nonce)
        tag_bytes = base64.b64decode(tag) if tag else None
        
        if "AES" in self.algorithm.upper():
            return self._decrypt_aes_gcm(ciphertext_bytes, nonce_bytes, tag_bytes)
        elif "CHACHA" in self.algorithm.upper():
            return self._decrypt_chacha20(ciphertext_bytes, nonce_bytes)
        elif "SALSA" in self.algorithm.upper():
            return self._decrypt_salsa20(ciphertext_bytes, nonce_bytes)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {self.algorithm}")
    
    def _encrypt_aes_gcm(self, plaintext: bytes) -> Dict[str, str]:
        """Encrypt using AES-GCM."""
        nonce = generate_nonce(12)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        return {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8'),
            "algorithm": self.algorithm,
        }
    
    def _decrypt_aes_gcm(self, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
        """Decrypt using AES-GCM."""
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    
    def _encrypt_chacha20(self, plaintext: bytes) -> Dict[str, str]:
        """Encrypt using ChaCha20."""
        nonce = generate_nonce(8)
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)
        
        return {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "algorithm": self.algorithm,
        }
    
    def _decrypt_chacha20(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """Decrypt using ChaCha20."""
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext
    
    def _encrypt_salsa20(self, plaintext: bytes) -> Dict[str, str]:
        """Encrypt using Salsa20."""
        nonce = generate_nonce(8)
        cipher = Salsa20.new(key=self.key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)
        
        return {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "algorithm": self.algorithm,
        }
    
    def _decrypt_salsa20(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """Decrypt using Salsa20."""
        cipher = Salsa20.new(key=self.key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext
    
    def encrypt_file(self, filepath: Union[str, Path], output_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
        """
        Encrypt a file.
        
        Args:
            filepath: Path to file to encrypt
            output_path: Output path (default: filepath.enc)
            
        Returns:
            Dictionary with encryption metadata
        """
        filepath = Path(filepath)
        output_path = Path(output_path or f"{filepath}.enc")
        
        with open(filepath, "rb") as f:
            data = f.read()
        
        result = self.encrypt(data)
        result["original_filename"] = filepath.name
        result["original_size"] = len(data)
        
        with open(output_path, "w") as f:
            json.dump(result, f)
        
        logger.info(f"Encrypted: {filepath} -> {output_path}")
        return result
    
    def decrypt_file(self, filepath: Union[str, Path], output_path: Optional[Union[str, Path]] = None) -> bytes:
        """
        Decrypt a file.
        
        Args:
            filepath: Path to encrypted file (JSON with ciphertext, nonce, tag)
            output_path: Output path for decrypted data
            
        Returns:
            Decrypted bytes
        """
        filepath = Path(filepath)
        
        with open(filepath, "r") as f:
            encrypted_data = json.load(f)
        
        decrypted = self.decrypt(
            ciphertext=encrypted_data["ciphertext"],
            nonce=encrypted_data["nonce"],
            tag=encrypted_data.get("tag"),
        )
        
        if output_path:
            output_path = Path(output_path)
            with open(output_path, "wb") as f:
                f.write(decrypted)
            logger.info(f"Decrypted: {filepath} -> {output_path}")
        
        return decrypted


# ==========================================
# HMAC Signing
# ==========================================

class HMACSigner:
    """
    HMAC-based message signing and verification.
    """
    
    def __init__(
        self,
        secret_key: Optional[bytes] = None,
        algorithm: str = "sha256",
    ):
        """
        Initialize HMAC signer.
        
        Args:
            secret_key: Secret key for signing (generated if None)
            algorithm: Hash algorithm (sha256, sha512, sha3_256, sha3_512)
        """
        self.secret_key = secret_key or generate_key(64)
        self.algorithm = algorithm
    
    def sign(self, message: Union[str, bytes]) -> str:
        """
        Sign a message with HMAC.
        
        Args:
            message: Message to sign
            
        Returns:
            Base64 encoded signature
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        h = hmac.new(self.secret_key, message, hashlib.new(self.algorithm))
        return base64.b64encode(h.digest()).decode('utf-8')
    
    def verify(self, message: Union[str, bytes], signature: str) -> bool:
        """
        Verify an HMAC signature.
        
        Args:
            message: Original message
            signature: Base64 encoded signature to verify
            
        Returns:
            True if signature is valid
        """
        expected = self.sign(message)
        return constant_time_compare(
            base64.b64decode(expected),
            base64.b64decode(signature),
        )
    
    def sign_request(self, method: str, path: str, body: str = "", timestamp: Optional[int] = None) -> Dict[str, str]:
        """
        Sign an HTTP request for API authentication.
        
        Args:
            method: HTTP method
            path: Request path
            body: Request body
            timestamp: Unix timestamp (generated if None)
            
        Returns:
            Dictionary with headers for API request
        """
        import time
        timestamp = timestamp or int(time.time())
        
        message = f"{method.upper()}:{path}:{body}:{timestamp}"
        signature = self.sign(message)
        
        return {
            "X-Signature": signature,
            "X-Timestamp": str(timestamp),
        }
    
    def verify_request(
        self,
        method: str,
        path: str,
        body: str,
        timestamp: int,
        signature: str,
        max_age: int = 300,
    ) -> Tuple[bool, str]:
        """
        Verify a signed API request.
        
        Args:
            method: HTTP method
            path: Request path
            body: Request body
            timestamp: Timestamp from request
            signature: Signature from request
            max_age: Maximum age of timestamp in seconds
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        import time
        
        # Check timestamp freshness
        current_time = int(time.time())
        if abs(current_time - timestamp) > max_age:
            return False, f"Request expired (age: {abs(current_time - timestamp)}s, max: {max_age}s)"
        
        # Verify signature
        message = f"{method.upper()}:{path}:{body}:{timestamp}"
        if self.verify(message, signature):
            return True, "Valid signature"
        
        return False, "Invalid signature"


# ==========================================
# Hash Utilities
# ==========================================

class HashUtils:
    """
    Hashing utilities for files and data.
    """
    
    @staticmethod
    def hash_data(
        data: Union[str, bytes],
        algorithm: str = DEFAULT_HASH_ALGORITHM,
    ) -> str:
        """
        Hash data.
        
        Args:
            data: Data to hash
            algorithm: Hash algorithm
            
        Returns:
            Hex digest string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        h = hashlib.new(algorithm)
        h.update(data)
        return h.hexdigest()
    
    @staticmethod
    def hash_file(
        filepath: Union[str, Path],
        algorithm: str = DEFAULT_HASH_ALGORITHM,
        chunk_size: int = 65536,
    ) -> Dict[str, Any]:
        """
        Hash a file.
        
        Args:
            filepath: Path to file
            algorithm: Hash algorithm
            chunk_size: Chunk size for reading
            
        Returns:
            Dictionary with hash info
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        
        file_size = filepath.stat().st_size
        h = hashlib.new(algorithm)
        
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                h.update(chunk)
        
        return {
            "file": filepath.name,
            "size": file_size,
            "algorithm": algorithm,
            "hash": h.hexdigest(),
        }
    
    @staticmethod
    def hash_directory(
        directory: Union[str, Path],
        algorithm: str = DEFAULT_HASH_ALGORITHM,
    ) -> Dict[str, str]:
        """
        Hash all files in a directory.
        
        Args:
            directory: Directory path
            algorithm: Hash algorithm
            
        Returns:
            Dictionary mapping filenames to hashes
        """
        directory = Path(directory)
        hashes = {}
        
        for filepath in directory.rglob("*"):
            if filepath.is_file():
                result = HashUtils.hash_file(filepath, algorithm)
                hashes[str(filepath.relative_to(directory))] = result["hash"]
        
        return hashes
    
    @staticmethod
    def verify_checksum(filepath: Union[str, Path], expected_hash: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> bool:
        """
        Verify file checksum.
        
        Args:
            filepath: Path to file
            expected_hash: Expected hex digest
            algorithm: Hash algorithm
            
        Returns:
            True if hash matches
        """
        result = HashUtils.hash_file(filepath, algorithm)
        return constant_time_compare(
            result["hash"].encode(),
            expected_hash.encode(),
        )
    
    @staticmethod
    def supported_algorithms() -> list:
        """Get list of supported hash algorithms."""
        return sorted(hashlib.algorithms_available)


# ==========================================
# Data Obfuscation (for API responses)
# ==========================================

class DataObfuscator:
    """
    Obfuscate API response data to prevent easy reverse engineering.
    """
    
    @staticmethod
    def obfuscate(data: Any, secret: Optional[bytes] = None) -> str:
        """
        Obfuscate data for transmission.
        
        Args:
            data: Data to obfuscate
            secret: Optional secret key for encryption
            
        Returns:
            Obfuscated string
        """
        # Convert to JSON
        json_data = json.dumps(data, ensure_ascii=False)
        
        # Compress
        compressed = zlib.compress(json_data.encode('utf-8'), level=9)
        
        # Encode
        if secret:
            # XOR with secret
            secret_repeated = (secret * (len(compressed) // len(secret) + 1))[:len(compressed)]
            compressed = bytes(a ^ b for a, b in zip(compressed, secret_repeated))
        
        # Base85 encode
        encoded = base64.b85encode(compressed)
        
        return encoded.decode('utf-8')
    
    @staticmethod
    def deobfuscate(encoded_data: str, secret: Optional[bytes] = None) -> Any:
        """
        Deobfuscate data.
        
        Args:
            encoded_data: Obfuscated string
            secret: Secret key used for obfuscation
            
        Returns:
            Original data
        """
        # Base85 decode
        decoded = base64.b85decode(encoded_data)
        
        # Decrypt
        if secret:
            secret_repeated = (secret * (len(decoded) // len(secret) + 1))[:len(decoded)]
            decoded = bytes(a ^ b for a, b in zip(decoded, secret_repeated))
        
        # Decompress
        json_data = zlib.decompress(decoded)
        
        # Parse JSON
        return json.loads(json_data)


# ==========================================
# Certificate Pinning
# ==========================================

class CertificatePinner:
    """
    SSL/TLS Certificate Pinning for preventing MITM attacks.
    """
    
    def __init__(self, allowed_hashes: Optional[list] = None):
        """
        Initialize certificate pinner.
        
        Args:
            allowed_hashes: List of allowed certificate SHA256 hashes
        """
        self.allowed_hashes = allowed_hashes or []
    
    def add_pin(self, cert_hash: str):
        """Add an allowed certificate hash."""
        if cert_hash not in self.allowed_hashes:
            self.allowed_hashes.append(cert_hash)
    
    def remove_pin(self, cert_hash: str):
        """Remove an allowed certificate hash."""
        if cert_hash in self.allowed_hashes:
            self.allowed_hashes.remove(cert_hash)
    
    def verify_certificate(self, cert_data: bytes) -> bool:
        """
        Verify a certificate against pinned hashes.
        
        Args:
            cert_data: Certificate data in DER or PEM format
            
        Returns:
            True if certificate is allowed
        """
        if not self.allowed_hashes:
            return True  # No pins configured
        
        cert_hash = hashlib.sha256(cert_data).hexdigest()
        return cert_hash in self.allowed_hashes
    
    def pin_certificate_from_file(self, filepath: Union[str, Path]):
        """
        Pin a certificate from a file.
        
        Args:
            filepath: Path to certificate file
        """
        filepath = Path(filepath)
        
        with open(filepath, "rb") as f:
            cert_data = f.read()
        
        cert_hash = hashlib.sha256(cert_data).hexdigest()
        self.add_pin(cert_hash)
        logger.info(f"Pinned certificate: {filepath.name} ({cert_hash[:16]}...)")
    
    def export_pins(self) -> list:
        """Export pinned certificate hashes."""
        return self.allowed_hashes.copy()
    
    def load_pins(self, pins: list):
        """Load pinned certificate hashes."""
        self.allowed_hashes = pins.copy()


# ==========================================
# Main Crypto Class
# ==========================================

class Crypto:
    """
    Main cryptography interface for IronStack.
    
    Provides a unified API for all cryptographic operations.
    
    Usage:
        >>> from ironstack.defense import Crypto
        >>> crypto = Crypto()
        >>> hashed = crypto.hash_password("my_password")
        >>> encrypted = crypto.encrypt("secret data")
        >>> signature = crypto.sign_request("GET", "/api/data")
    """
    
    def __init__(
        self,
        encryption_algorithm: str = DEFAULT_ENCRYPTION_ALGORITHM,
        hash_algorithm: str = DEFAULT_HASH_ALGORITHM,
        signing_algorithm: str = DEFAULT_SIGNING_ALGORITHM,
        secret_key: Optional[bytes] = None,
    ):
        """
        Initialize Crypto.
        
        Args:
            encryption_algorithm: Default encryption algorithm
            hash_algorithm: Default hash algorithm
            signing_algorithm: Default signing algorithm
            secret_key: Master secret key
        """
        self.encryption_algorithm = encryption_algorithm
        self.hash_algorithm = hash_algorithm
        self.signing_algorithm = signing_algorithm
        self.secret_key = secret_key or generate_key(64)
        
        # Initialize sub-components
        self.hasher = PasswordHasher()
        self.signer = HMACSigner(secret_key=self.secret_key, algorithm=hash_algorithm)
        self.obfuscator = DataObfuscator()
        self.cert_pinner = CertificatePinner()
        
        if CRYPTO_AVAILABLE:
            self.encryptor = SymmetricEncryption(
                algorithm=encryption_algorithm,
                key=self.secret_key[:32],
            )
        else:
            self.encryptor = None
        
        logger.info("🔐 Crypto module initialized")
    
    # ==========================================
    # Password Operations
    # ==========================================
    
    def hash_password(self, password: str, **kwargs) -> Dict[str, Any]:
        """Hash a password."""
        return self.hasher.hash_password(password, **kwargs)
    
    def verify_password(self, password: str, stored_hash: str, stored_salt: str, **kwargs) -> bool:
        """Verify a password."""
        return self.hasher.verify_password(password, stored_hash, stored_salt, **kwargs)
    
    def check_password_strength(self, password: str) -> Dict[str, Any]:
        """Check password strength."""
        return self.hasher.check_password_strength(password)
    
    # ==========================================
    # Encryption Operations
    # ==========================================
    
    def encrypt(self, data: Union[str, bytes]) -> Dict[str, str]:
        """Encrypt data."""
        if not self.encryptor:
            raise ImportError("PyCryptodome required for encryption")
        return self.encryptor.encrypt(data)
    
    def decrypt(self, ciphertext: str, nonce: str, tag: Optional[str] = None) -> bytes:
        """Decrypt data."""
        if not self.encryptor:
            raise ImportError("PyCryptodome required for encryption")
        return self.encryptor.decrypt(ciphertext, nonce, tag)
    
    def encrypt_file(self, filepath: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """Encrypt a file."""
        if not self.encryptor:
            raise ImportError("PyCryptodome required for encryption")
        return self.encryptor.encrypt_file(filepath, output_path)
    
    def decrypt_file(self, filepath: str, output_path: Optional[str] = None) -> bytes:
        """Decrypt a file."""
        if not self.encryptor:
            raise ImportError("PyCryptodome required for encryption")
        return self.encryptor.decrypt_file(filepath, output_path)
    
    # ==========================================
    # Signing Operations
    # ==========================================
    
    def sign(self, message: Union[str, bytes]) -> str:
        """Sign a message."""
        return self.signer.sign(message)
    
    def verify(self, message: Union[str, bytes], signature: str) -> bool:
        """Verify a signature."""
        return self.signer.verify(message, signature)
    
    def sign_request(self, method: str, path: str, body: str = "", timestamp: Optional[int] = None) -> Dict[str, str]:
        """Sign an API request."""
        return self.signer.sign_request(method, path, body, timestamp)
    
    def verify_request(self, method: str, path: str, body: str, timestamp: int, signature: str, max_age: int = 300) -> Tuple[bool, str]:
        """Verify an API request."""
        return self.signer.verify_request(method, path, body, timestamp, signature, max_age)
    
    # ==========================================
    # Hash Operations
    # ==========================================
    
    def hash_data(self, data: Union[str, bytes], algorithm: Optional[str] = None) -> str:
        """Hash data."""
        return HashUtils.hash_data(data, algorithm or self.hash_algorithm)
    
    def hash_file(self, filepath: str, algorithm: Optional[str] = None) -> Dict[str, Any]:
        """Hash a file."""
        return HashUtils.hash_file(filepath, algorithm or self.hash_algorithm)
    
    def verify_checksum(self, filepath: str, expected_hash: str, algorithm: Optional[str] = None) -> bool:
        """Verify file checksum."""
        return HashUtils.verify_checksum(filepath, expected_hash, algorithm or self.hash_algorithm)
    
    # ==========================================
    # Obfuscation Operations
    # ==========================================
    
    def obfuscate(self, data: Any) -> str:
        """Obfuscate data for API responses."""
        return self.obfuscator.obfuscate(data, self.secret_key[:16])
    
    def deobfuscate(self, encoded_data: str) -> Any:
        """Deobfuscate data."""
        return self.obfuscator.deobfuscate(encoded_data, self.secret_key[:16])
    
    # ==========================================
    # Certificate Pinning Operations
    # ==========================================
    
    def pin_certificate(self, filepath: str):
        """Pin a certificate."""
        self.cert_pinner.pin_certificate_from_file(filepath)
    
    def verify_certificate(self, cert_data: bytes) -> bool:
        """Verify a certificate."""
        return self.cert_pinner.verify_certificate(cert_data)
    
    # ==========================================
    # Utility
    # ==========================================
    
    def generate_token(self, length: int = 32) -> str:
        """Generate a secure random token."""
        return secrets.token_hex(length)
    
    def generate_api_key(self) -> str:
        """Generate a secure API key."""
        return f"is_{secrets.token_hex(24)}"
    
    def rotate_keys(self):
        """Rotate all cryptographic keys."""
        self.secret_key = generate_key(64)
        self.signer = HMACSigner(secret_key=self.secret_key, algorithm=self.hash_algorithm)
        if self.encryptor:
            self.encryptor = SymmetricEncryption(
                algorithm=self.encryption_algorithm,
                key=self.secret_key[:32],
            )
        logger.info("🔑 Keys rotated successfully")
    
    def __repr__(self) -> str:
        return f"Crypto(encryption='{self.encryption_algorithm}', hash='{self.hash_algorithm}')"
