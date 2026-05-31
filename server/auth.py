"""
Autenticação de utilizadores.

Gere o registo e a verificação de credenciais. As palavras-passe nunca são
guardadas em claro: armazena-se apenas um hash com salt único por utilizador.
"""

import hashlib
import os
from db import get_connection


def init_users_table():
    """Cria a tabela de utilizadores, se ainda não existir.

    Guarda o hash da password e o salt (nunca a password em claro). O email é
    UNIQUE para impedir contas duplicadas com o mesmo endereço.
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
    """Calcula o hash da password concatenada com o salt.

    O salt (único por utilizador) garante que duas contas com a mesma password
    produzem hashes diferentes, inutilizando ataques por rainbow tables.

    Nota de segurança: SHA-256 numa única passagem é rápido, o que o torna
    vulnerável a ataques de força bruta/dicionário. Uma versão mais robusta
    usaria uma função lenta e dedicada a passwords (PBKDF2, bcrypt ou Argon2).

    Args:
        password: a palavra-passe em texto simples.
        salt: o salt aleatório em hexadecimal.

    Returns:
        O hash resultante em representação hexadecimal.
    """
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def register_user(email: str, password: str) -> tuple[bool, str]:
    """Regista um novo utilizador.

    Rejeita o registo se o email já existir. Caso contrário, gera um salt
    aleatório, calcula o hash da password e grava o utilizador.

    Args:
        email: o email do utilizador (já normalizado pela camada que chama).
        password: a palavra-passe a proteger.

    Returns:
        Um par (sucesso, mensagem): (True, ...) se a conta foi criada,
        (False, ...) com o motivo se não foi.
    """
    init_users_table()
    conn = get_connection()
    cursor = conn.cursor()

    # Consulta parametrizada (?): o valor é passado separadamente da query,
    # o que previne injeção de SQL através do email.
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return False, "Este email já está registado."

    # Salt aleatório de 16 bytes, único para este utilizador.
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
    """Verifica as credenciais de um utilizador.

    Recalcula o hash a partir da password fornecida e do salt guardado, e
    compara-o com o hash armazenado. Não há acesso à password original em
    momento nenhum.

    Args:
        email: o email do utilizador.
        password: a palavra-passe a verificar.

    Returns:
        True se as credenciais forem válidas, False caso contrário (incluindo
        quando o email não existe).
    """
    init_users_table()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT password_hash, salt FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return False

    # Refaz o hash com o salt guardado e compara com o hash em base de dados.
    expected = _hash_password(password, row["salt"])
    return expected == row["password_hash"]