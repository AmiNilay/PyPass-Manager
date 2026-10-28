"""Symmetric encryption helpers (Fernet / PBKDF2) for the password manager."""

import base64
import logging
import os
from typing import Union

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

SALT_SIZE = 16

# PBKDF2 iterations for key derivation. Changing this breaks existing vaults.
KDF_ITERATIONS = 480_000

# Returned by decrypt_data when a token cannot be decrypted with the given key.
DECRYPTION_ERROR = "[Decryption Error]"


def generate_salt(size: int = SALT_SIZE) -> bytes:
    """Returns a cryptographically secure random salt."""
    return os.urandom(size)


def derive_key(master_password: Union[str, bytes], salt: bytes) -> bytes:
    """Derives a urlsafe-base64 Fernet key from a password and salt (PBKDF2-SHA256)."""
    password = master_password if isinstance(master_password, bytes) else master_password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def encrypt_data(data: str, key: bytes) -> bytes:
    """Encrypts a string with a Fernet key. Empty input returns b''."""
    if not data:
        return b""
    return Fernet(key).encrypt(data.encode("utf-8"))


def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypts a Fernet token. Returns "" for empty input and DECRYPTION_ERROR on failure."""
    if not encrypted_data:
        return ""
    try:
        return Fernet(key).decrypt(encrypted_data).decode("utf-8")
    except Exception as e:
        logger.error("Decryption failed: %s", type(e).__name__)
        return DECRYPTION_ERROR


def generate_vault_key() -> bytes:
    """Generates a random Fernet key used to encrypt all vault data."""
    return Fernet.generate_key()


def wrap_key(key: bytes, wrapping_key: bytes) -> str:
    """Encrypts a key with another (derived) key; returns a storable string."""
    return Fernet(wrapping_key).encrypt(key).decode("utf-8")


def unwrap_key(wrapped: str, wrapping_key: bytes) -> bytes:
    """Reverses wrap_key. Raises cryptography.fernet.InvalidToken on a wrong key."""
    return Fernet(wrapping_key).decrypt(wrapped.encode("utf-8"))
