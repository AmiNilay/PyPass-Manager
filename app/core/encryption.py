# password_manager/app/core/encryption.py
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Use a fixed salt size for consistency
SALT_SIZE = 16

def generate_salt(size=SALT_SIZE) -> bytes:
    """Generates a cryptographically secure random salt."""
    return os.urandom(size)

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derives a secure encryption key from the master password and salt."""
    if not isinstance(master_password, bytes):
        password = master_password.encode('utf-8')
    else:
        password = master_password

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Use 32 bytes for AES-256 compatibility with Fernet
        salt=salt,
        iterations=480000, # NIST recommended minimum iterations (as of 2023)
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_data(data: str, key: bytes) -> bytes:
    """Encrypts data using the derived Fernet key."""
    if not data:
        return b''
    f = Fernet(key)
    return f.encrypt(data.encode('utf-8'))

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypts data using the derived Fernet key."""
    if not encrypted_data:
        return ""
    try:
        f = Fernet(key)
        decrypted_bytes = f.decrypt(encrypted_data)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"Decryption failed: {e}") # Log this properly in a real app
        # Returning an empty string or raising a specific error might be better
        # depending on how the caller handles failures.
        return "[Decryption Error]"