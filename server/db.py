"""
Acesso à base de dados SQLite.

Centraliza a abertura de ligações e a criação do esquema (tabelas de ficheiros
cifrados e de utilizadores).
"""

import os
import sqlite3

from config import DATABASE_PATH


def get_connection():
    """Abre uma ligação à base de dados SQLite.

    Garante que a pasta da base de dados existe antes de ligar e define o
    row_factory como sqlite3.Row, o que permite aceder às colunas pelo nome
    (ex.: row["email"]) em vez de por índice.

    Returns:
        Um objeto de ligação sqlite3 pronto a usar.
    """
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Cria as tabelas da aplicação, se ainda não existirem.

    Define duas tabelas: 'encrypted_files' (histórico das operações de cifra,
    apenas metadados — nunca chaves nem conteúdo) e 'users' (credenciais, com a
    password guardada como hash + salt e o email único).

    O CREATE TABLE IF NOT EXISTS torna a função idempotente: pode ser chamada em
    todos os arranques sem apagar nem duplicar dados.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Histórico de cifras: guarda só metadados da operação.
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

    # Utilizadores: email único e password protegida (hash + salt).
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