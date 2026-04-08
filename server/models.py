from db import get_connection


def insert_encrypted_file(
    email,
    original_filename,
    scheduled_datetime,
    aes_mode,
    hmac_mode,
    file_path,
    created_at,
):
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


def get_all_encrypted_files():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM encrypted_files ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()

    return rows