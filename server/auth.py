import hashlib
import os
from db import get_connection


def init_users_table():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def _hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def register_user(email: str, password: str) -> tuple[bool, str]:
    init_users_table()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return False, "Este email já está registado."

    salt = os.urandom(16).hex()
    password_hash = _hash_password(password, salt)

    from datetime import datetime
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        "INSERT INTO users (email, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
        (email, password_hash, salt, created_at),
    )
    conn.commit()
    conn.close()
    return True, "Conta criada."


def verify_user(email: str, password: str) -> bool:
    init_users_table()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT password_hash, salt FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return False

    expected = _hash_password(password, row["salt"])
    return expected == row["password_hash"]