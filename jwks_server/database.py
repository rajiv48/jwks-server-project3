
"""SQLite database initialization and connection management."""

import sqlite3
from pathlib import Path

DB_PATH = Path("totally_not_my_privateKeys.db")


def get_connection(db_path=DB_PATH):
    """Create a connection to the SQLite database."""
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def initialize_database(db_path=DB_PATH):
    """Create the required database tables."""
    connection = get_connection(db_path)

    try:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS keys (
                kid TEXT PRIMARY KEY,
                encrypted_key BLOB NOT NULL,
                nonce BLOB NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        """)

        connection.commit()

    finally:
        connection.close()