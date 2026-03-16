from flask import Flask, render_template, request, Response
from crypto_utils import (
    derive_current_key,
    derive_future_key,
    derive_keys,
    encrypt_file_aes_cbc,
    compute_hmac_sha256,
    build_encrypted_package,
    load_encrypted_package,
    verify_hmac_sha256,
    decrypt_file_aes_cbc,
    is_unlock_time_reached
)
from db import init_db
from models import insert_encrypted_file, get_all_encrypted_files
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

init_db()

@app.route("/", methods=["GET", "POST"])
def index():
    current_result = None
    future_result = None
    error = None

    if request.method == "POST":
        form_type = request.form.get("form_type")
        email = request.form.get("email", "").strip()

        try:
            if form_type == "current_key":
                if email:
                    current_result = derive_current_key(email)

            elif form_type == "future_key":
                future_datetime = request.form.get("future_datetime", "").strip()

                if email and future_datetime:
                    future_result = derive_future_key(email, future_datetime)

        except Exception as e:
            error = f"Erro: {str(e)}"

    return render_template(
        "index.html",
        current_result=current_result,
        future_result=future_result,
        error=error
    )

@app.route("/encrypt", methods=["GET", "POST"])
def encrypt_page():
    error = None

    if request.method == "POST":
        try:
            email = request.form.get("email", "").strip()
            future_datetime = request.form.get("future_datetime", "").strip()
            uploaded_file = request.files.get("file")

            if not email or not future_datetime or not uploaded_file:
                raise ValueError("Preenche o email, a data/hora e escolhe um ficheiro.")

            key_data = derive_future_key(email, future_datetime)
            file_bytes = uploaded_file.read()

            encrypted_data = encrypt_file_aes_cbc(file_bytes, key_data["aes_key_bytes"])

            hmac_tag = compute_hmac_sha256(
                hmac_key_bytes=key_data["hmac_key_bytes"],
                email=key_data["email"],
                timestamp=key_data["timestamp"],
                algorithm="AES-128-CBC",
                original_filename=uploaded_file.filename,
                iv=encrypted_data["iv"],
                ciphertext=encrypted_data["ciphertext"]
            )

            encrypted_package = build_encrypted_package(
                email=key_data["email"],
                timestamp=key_data["timestamp"],
                original_filename=uploaded_file.filename,
                iv=encrypted_data["iv"],
                ciphertext=encrypted_data["ciphertext"],
                hmac_tag=hmac_tag
            )

            output_filename = f"{uploaded_file.filename}.encrypted.json"

            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            insert_encrypted_file(
                email=key_data["email"],
                original_filename=uploaded_file.filename,
                scheduled_datetime=key_data["timestamp"],
                aes_mode="AES-128-CBC",
                hmac_mode="HMAC-SHA256",
                file_path=output_filename,
                created_at=created_at
            )

            return Response(
                encrypted_package,
                mimetype="application/json",
                headers={
                    "Content-Disposition": f"attachment; filename={output_filename}"
                }
            )

        except Exception as e:
            error = f"Erro: {str(e)}"

    return render_template("encrypt.html", error=error)

@app.route("/decrypt", methods=["GET", "POST"])
def decrypt_page():
    error = None

    if request.method == "POST":
        try:
            key_hex = request.form.get("key_hex", "").strip()
            uploaded_file = request.files.get("file")

            if not key_hex or not uploaded_file:
                raise ValueError("Fornece a chave AES e o ficheiro cifrado.")

            package = load_encrypted_package(uploaded_file.read())

            if not is_unlock_time_reached(package["timestamp"]):
                raise ValueError(
                    f"O ficheiro só pode ser decifrado a partir de {package['timestamp']}.")

            key_data = derive_keys(package["email"], package["timestamp"])

            hmac_valid = verify_hmac_sha256(
                hmac_key_bytes=key_data["hmac_key_bytes"],
                email=package["email"],
                timestamp=package["timestamp"],
                algorithm=package["algorithm"],
                original_filename=package["original_filename"],
                iv=package["iv"],
                ciphertext=package["ciphertext"],
                received_hmac=package["hmac"]
            )

            if not hmac_valid:
                raise ValueError("Falha na verificação de integridade: HMAC inválido.")

            aes_key_bytes = bytes.fromhex(key_hex)

            plaintext = decrypt_file_aes_cbc(
                ciphertext=package["ciphertext"],
                key_bytes=aes_key_bytes,
                iv=package["iv"]
            )

            return Response(
                plaintext,
                mimetype="application/octet-stream",
                headers={
                    "Content-Disposition": f"attachment; filename={package['original_filename']}"
                }
            )

        except Exception as e:
            error = f"Erro: {str(e)}"

    return render_template("decrypt.html", error=error)

@app.route("/history")
def history_page():
    records = get_all_encrypted_files()
    return render_template("history.html", records=records)

if __name__ == "__main__":
    app.run(debug=True)