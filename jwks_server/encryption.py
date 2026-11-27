
"""AES encryption and decryption of RSA private keys."""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def get_encryption_key():
    """Read the AES key from the environment variable."""
    secret = os.environ.get("NOT_MY_KEY")

    if not secret:
        raise RuntimeError("NOT_MY_KEY environment variable is missing")

    key = bytes.fromhex(secret)

    if len(key) != 32:
        raise ValueError("NOT_MY_KEY must contain a 256-bit key")

    return key


def encrypt_private_key(private_key_bytes):
    """Encrypt private key bytes using AES-256-GCM."""
    key = get_encryption_key()
    aes = AESGCM(key)

    nonce = os.urandom(12)

    encrypted_key = aes.encrypt(
        nonce,
        private_key_bytes,
        None
    )

    return encrypted_key, nonce


def decrypt_private_key(encrypted_key, nonce):
    """Decrypt an encrypted private key."""
    key = get_encryption_key()
    aes = AESGCM(key)

    decrypted_key = aes.decrypt(
        nonce,
        encrypted_key,
        None
    )

    return decrypted_key
