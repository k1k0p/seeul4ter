import hashlib
import os
from db import get_connection


def init_users_table():
    """
    Inicializa a tabela de utilizadores na base de dados, caso não exista.
    Cria os campos necessários para armazenamento seguro de credenciais.
    """
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
    """
    Calcula o hash SHA-256 de uma palavra-passe utilizando um salt para maior segurança.
    @param password: A palavra-passe em texto simples.
    @param salt: A string de salt aleatória.
    @return: A representação hexadecimal do hash final.
    """
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def register_user(email: str, password: str) -> tuple[bool, str]:
    """
    Regista um novo utilizador na base de dados após verificar se o email já existe.
    @param email: O email do utilizador.
    @param password: A palavra-passe a ser protegida.
    @return: Um tuple com (sucesso, mensagem).
    """
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
    """
    Verifica se as credenciais fornecidas são válidas, comparando o hash calculado com o armazenado.
    @param email: O email do utilizador.
    @param password: A palavra-passe a verificar.
    @return: True se as credenciais estiverem corretas, False caso contrário.
    """
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