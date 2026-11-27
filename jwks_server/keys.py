
"""RSA key management with encrypted SQLite storage."""

from __future__ import annotations

import base64
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from jwks_server.database import (
    DB_PATH,
    get_connection,
    initialize_database,
)
from jwks_server.encryption import (
    encrypt_private_key,
    decrypt_private_key,
    get_encryption_key,
)

KEY_SIZE_BITS = 2048
PUBLIC_EXPONENT = 65537
DEFAULT_KEY_LIFETIME = timedelta(hours=1)

Clock = Callable[[], datetime]


def utcnow() -> datetime:
    """Return the current UTC time."""
    return datetime.now(UTC)


def _b64url_uint(value: int) -> str:
    """Encode an integer as unpadded base64url."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class KeyRecord:
    """RSA key pair with its ID and expiration time."""

    kid: str
    private_key: rsa.RSAPrivateKey
    expires_at: datetime

    def is_expired(self, now: datetime) -> bool:
        """Check whether the key has expired."""
        return self.expires_at <= now

    def to_jwk(self) -> dict[str, str]:
        """Return only the public key information."""
        numbers = self.private_key.public_key().public_numbers()

        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": _b64url_uint(numbers.n),
            "e": _b64url_uint(numbers.e),
        }


def generate_key(expires_at: datetime) -> KeyRecord:
    """Generate a new RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE_BITS,
    )

    return KeyRecord(
        kid=uuid.uuid4().hex,
        private_key=private_key,
        expires_at=expires_at,
    )


class KeyStore:
    """Manage RSA keys using encrypted SQLite storage."""

    def __init__(
        self,
        lifetime: timedelta = DEFAULT_KEY_LIFETIME,
        clock: Clock = utcnow,
        db_path=DB_PATH,
    ) -> None:
        """Initialize the database and required RSA keys."""
        self._lifetime = lifetime
        self._clock = clock
        self._lock = threading.Lock()
        self._db_path = db_path

        get_encryption_key()
        initialize_database(self._db_path)

        now = self._clock()
        keys = self._load_keys()

        if not any(key.is_expired(now) for key in keys):
            self._save_key(generate_key(now - lifetime))

        if not any(not key.is_expired(now) for key in keys):
            self._save_key(generate_key(now + lifetime))

    def _save_key(self, record: KeyRecord) -> None:
        """Encrypt and store an RSA private key."""
        private_bytes = record.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        encrypted_key, nonce = encrypt_private_key(private_bytes)

        connection = get_connection(self._db_path)

        try:
            connection.execute(
                """
                INSERT INTO keys
                (kid, encrypted_key, nonce, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    record.kid,
                    encrypted_key,
                    nonce,
                    int(record.expires_at.timestamp()),
                ),
            )

            connection.commit()

        finally:
            connection.close()

    def _load_keys(self) -> list[KeyRecord]:
        """Retrieve and decrypt stored RSA private keys."""
        connection = get_connection(self._db_path)

        try:
            rows = connection.execute(
                """
                SELECT kid, encrypted_key, nonce, expires_at
                FROM keys
                """
            ).fetchall()

        finally:
            connection.close()

        keys = []

        for row in rows:
            private_bytes = decrypt_private_key(
                row["encrypted_key"],
                row["nonce"],
            )

            private_key = serialization.load_pem_private_key(
                private_bytes,
                password=None,
            )

            record = KeyRecord(
                kid=row["kid"],
                private_key=private_key,
                expires_at=datetime.fromtimestamp(
                    row["expires_at"],
                    tz=UTC,
                ),
            )

            keys.append(record)

        return keys

    def now(self) -> datetime:
        """Return the current time."""
        return self._clock()

    def unexpired_keys(self) -> list[KeyRecord]:
        """Return all valid RSA keys."""
        with self._lock:
            now = self._clock()
            self._ensure_active_locked(now)

            return [
                key for key in self._load_keys()
                if not key.is_expired(now)
            ]

    def active_key(self) -> KeyRecord:
        """Return the active RSA signing key."""
        with self._lock:
            now = self._clock()
            self._ensure_active_locked(now)

            valid = [
                key for key in self._load_keys()
                if not key.is_expired(now)
            ]

            return max(valid, key=lambda key: key.expires_at)

    def expired_key(self) -> KeyRecord:
        """Return the most recently expired RSA key."""
        with self._lock:
            now = self._clock()

            expired = [
                key for key in self._load_keys()
                if key.is_expired(now)
            ]

            return max(expired, key=lambda key: key.expires_at)

    def _ensure_active_locked(self, now: datetime) -> None:
        """Generate a new key if all existing keys have expired."""
        keys = self._load_keys()

        if all(key.is_expired(now) for key in keys):
            self._save_key(
                generate_key(now + self._lifetime)
            )
