import os
import sqlite3

from config import DATABASE_PATH


def get_connection():
    """
    Estabelece uma ligação à base de dados SQLite.
    Garante que o diretório da base de dados existe antes de conectar.
    @return: Objeto de conexão sqlite3 configurado com row_factory.
    """
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Inicializa a estrutura da base de dados, criando as tabelas necessárias
    para o registo de ficheiros cifrados e gestão de utilizadores.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS encrypted_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            scheduled_datetime TEXT NOT NULL,
            aes_mode TEXT NOT NULL,
            hmac_mode TEXT NOT NULL,
            file_path TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

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