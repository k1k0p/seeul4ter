from db import get_connection


def insert_encrypted_file(
    email: str,
    original_filename: str,
    scheduled_datetime: str,
    aes_mode: str,
    hmac_mode: str,
    file_path: str,
    created_at: str,
) -> int:
    """
    Insere um novo registo de ficheiro cifrado na base de dados.
    @param email: Email do utilizador.
    @param original_filename: Nome original do ficheiro.
    @param scheduled_datetime: Data/hora agendada para decifra.
    @param aes_mode: Modo de cifragem AES utilizado.
    @param hmac_mode: Algoritmo HMAC utilizado.
    @param file_path: Caminho do ficheiro cifrado.
    @param created_at: Data/hora de criação do registo.
    @return: O ID do novo registo inserido.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO encrypted_files (
            email,
            original_filename,
            scheduled_datetime,
            aes_mode,
            hmac_mode,
            file_path,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            email,
            original_filename,
            scheduled_datetime,
            aes_mode,
            hmac_mode,
            file_path,
            created_at,
        ),
    )

    conn.commit()
    inserted_id = cursor.lastrowid
    conn.close()

    return inserted_id


def get_all_encrypted_files() -> list:
    """
    Recupera todos os registos de ficheiros cifrados, ordenados do mais recente para o mais antigo.
    @return: Lista de objetos Row da base de dados.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM encrypted_files ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()

    return rows


def get_encrypted_files_by_email(email: str) -> list:
    """
    Recupera todos os registos de ficheiros cifrados associados a um utilizador específico.
    @param email: Email do utilizador.
    @return: Lista de registos filtrados.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM encrypted_files WHERE email = ? ORDER BY id DESC",
        (email,),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows