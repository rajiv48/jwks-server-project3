
"""User registration and password management."""

import sqlite3
import uuid

from argon2 import PasswordHasher

from jwks_server.database import DB_PATH, get_connection


password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def register_user(username, email, db_path=DB_PATH):
    """Register a user and return a generated password."""

    password = str(uuid.uuid4())

    password_hash = password_hasher.hash(password)

    connection = get_connection(db_path)

    try:
        connection.execute(
            """
            INSERT INTO users (username, password_hash, email)
            VALUES (?, ?, ?)
            """,
            (username, password_hash, email),
        )

        connection.commit()

    except sqlite3.IntegrityError:
        connection.rollback()
        raise

    finally:
        connection.close()

    return password
