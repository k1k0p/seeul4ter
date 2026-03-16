from flask import Flask, render_template, request, Response
from crypto_utils import (
    derive_current_key,
    derive_future_key,
    encrypt_file_aes_cbc,
    compute_hmac_sha256,
    build_encrypted_package
)
from db import init_db
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

if __name__ == "__main__":
    app.run(debug=True)