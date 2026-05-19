from datetime import datetime
import os
import functools

from flask import Flask, Response, render_template, request, redirect, url_for, session, flash

from crypto_utils import (
    build_encrypted_package,
    compute_hmac,
    decrypt_file,
    derive_current_key,
    derive_future_key,
    derive_keys,
    encrypt_file,
    is_unlock_time_reached,
    load_encrypted_package,
    verify_hmac,
)
from db import init_db
from models import get_all_encrypted_files, insert_encrypted_file
from auth import register_user, verify_user  # vamos criar este ficheiro

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

app.secret_key = "chave-secreta-da-sessao-flask"  # muda para algo mais seguro

init_db()


# ─── Autenticação ────────────────────────────────────────────────────────────

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "user_email" not in session:
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


@app.route("/register", methods=["GET", "POST"])
def register_page():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        if not email or not password:
            error = "Preenche o email e a password."
        else:
            ok, msg = register_user(email, password)
            if ok:
                flash("Conta criada com sucesso! Faz login.", "success")
                return redirect(url_for("login_page"))
            else:
                error = msg
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login_page():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        if verify_user(email, password):
            session["user_email"] = email
            return redirect(url_for("index"))
        else:
            error = "Email ou password incorretos."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ─── Páginas principais ──────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    current_result = None
    future_result = None
    error = None

    if request.method == "POST":
        form_type = request.form.get("form_type")
        email = request.form.get("email", "").strip()

        try:
            if form_type == "current_key":
                if not email:
                    raise ValueError("Tens de indicar um email.")
                current_result = derive_current_key(email)

            elif form_type == "future_key":
                future_datetime = request.form.get("future_datetime", "").strip()
                if not email or not future_datetime:
                    raise ValueError("Tens de indicar o email e a data/hora futura.")
                future_result = derive_future_key(email, future_datetime)

        except Exception as exc:
            error = f"Erro: {exc}"

    return render_template(
        "index.html",
        current_result=current_result,
        future_result=future_result,
        error=error,
    )


@app.route("/encrypt", methods=["GET", "POST"])
@login_required
def encrypt_page():
    error = None

    if request.method == "POST":
        try:
            email = request.form.get("email", "").strip()
            future_datetime = request.form.get("future_datetime", "").strip()
            uploaded_file = request.files.get("file")
            aes_mode = request.form.get("aes_mode", "AES-128-CBC")
            hmac_algorithm = request.form.get("hmac_mode", "HMAC-SHA256")

            if aes_mode not in ("AES-128-CBC", "AES-128-CTR"):
                aes_mode = "AES-128-CBC"
            if hmac_algorithm not in ("HMAC-SHA256", "HMAC-SHA512"):
                hmac_algorithm = "HMAC-SHA256"

            if not email or not future_datetime or not uploaded_file:
                raise ValueError("Preenche o email, a data/hora e escolhe um ficheiro.")

            key_data = derive_future_key(email, future_datetime)
            file_bytes = uploaded_file.read()

            if not file_bytes:
                raise ValueError("O ficheiro selecionado está vazio.")

            encrypted_data = encrypt_file(file_bytes, key_data["aes_key_bytes"], aes_mode)

            hmac_tag = compute_hmac(
                hmac_key_bytes=key_data["hmac_key_bytes"],
                email=key_data["email"],
                timestamp=key_data["timestamp"],
                algorithm=aes_mode,
                hmac_algorithm=hmac_algorithm,
                original_filename=uploaded_file.filename,
                iv=encrypted_data["iv"],
                ciphertext=encrypted_data["ciphertext"],
            )

            encrypted_package = build_encrypted_package(
                email=key_data["email"],
                timestamp=key_data["timestamp"],
                original_filename=uploaded_file.filename,
                aes_mode=aes_mode,
                hmac_algorithm=hmac_algorithm,
                iv=encrypted_data["iv"],
                ciphertext=encrypted_data["ciphertext"],
                hmac_tag=hmac_tag,
            )

            output_filename = f"{uploaded_file.filename}.encrypted.json"
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            insert_encrypted_file(
                email=key_data["email"],
                original_filename=uploaded_file.filename,
                scheduled_datetime=key_data["timestamp"],
                aes_mode=aes_mode,
                hmac_mode=hmac_algorithm,
                file_path=output_filename,
                created_at=created_at,
            )

            return Response(
                encrypted_package,
                mimetype="application/json",
                headers={"Content-Disposition": f"attachment; filename={output_filename}"},
            )

        except Exception as exc:
            error = f"Erro: {exc}"

    return render_template("encrypt.html", error=error)


@app.route("/decrypt", methods=["GET", "POST"])
@login_required
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
                    f"O ficheiro só pode ser decifrado a partir de {package['timestamp']}."
                )

            key_data = derive_keys(package["email"], package["timestamp"])

            hmac_valid = verify_hmac(
                hmac_key_bytes=key_data["hmac_key_bytes"],
                email=package["email"],
                timestamp=package["timestamp"],
                algorithm=package["algorithm"],
                hmac_algorithm=package["hmac_algorithm"],
                original_filename=package["original_filename"],
                iv=package["iv"],
                ciphertext=package["ciphertext"],
                received_hmac=package["hmac"],
            )

            if not hmac_valid:
                raise ValueError("Falha na verificação de integridade: HMAC inválido.")

            try:
                aes_key_bytes = bytes.fromhex(key_hex)
            except ValueError as exc:
                raise ValueError("A chave AES tem de estar em formato hexadecimal válido.") from exc

            if aes_key_bytes != key_data["aes_key_bytes"]:
                raise ValueError(
                    "A chave AES fornecida não corresponde ao email/data-hora do ficheiro."
                )

            plaintext = decrypt_file(
                ciphertext=package["ciphertext"],
                key_bytes=aes_key_bytes,
                iv=package["iv"],
                aes_mode=package["algorithm"],
            )

            return Response(
                plaintext,
                mimetype="application/octet-stream",
                headers={"Content-Disposition": f"attachment; filename={package['original_filename']}"},
            )

        except Exception as exc:
            error = f"Erro: {exc}"

    return render_template("decrypt.html", error=error)


@app.route("/history")
@login_required
def history_page():
    records = get_all_encrypted_files()
    return render_template("history.html", records=records)


if __name__ == "__main__":
    app.run(debug=True)