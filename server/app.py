from datetime import datetime, timedelta
import os
import functools

from flask import Flask, Response, render_template, request, redirect, url_for, session, flash

from crypto_utils import (
    build_encrypted_package,
    compute_hmac,
    decrypt_file,
    derive_current_key,
    derive_past_key,
    derive_future_key,
    derive_keys,
    encrypt_file,
    is_unlock_time_reached,
    load_encrypted_package,
    sign_package,
    verify_hmac,
    verify_signature,
)
from db import init_db
from models import get_all_encrypted_files, insert_encrypted_file, get_encrypted_files_by_email
from auth import register_user, verify_user
from system_keys import ensure_system_keypair, load_private_key, load_public_key, get_public_key_pem
from config import FLASK_SECRET_KEY

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

app.secret_key = FLASK_SECRET_KEY

init_db()
ensure_system_keypair()  # gera o par RSA do sistema na primeira execução


# ─── Autenticação ────────────────────────────────────────────────────────────

def login_required(f):
    """
    Decorador para restringir o acesso a rotas apenas a utilizadores autenticados.
    @param f: A função da rota a ser decorada.
    @return: A função decorada que redireciona para o login se necessário.
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "user_email" not in session:
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


@app.route("/register", methods=["GET", "POST"])
def register_page():
    """
    Processa o registo de novos utilizadores.
    @return: Renderiza o template de registo com mensagens de erro ou sucesso.
    """
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
    """
    Processa a autenticação do utilizador.
    @return: Redireciona para o índice se o login for bem-sucedido.
    """
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
    """
    Termina a sessão do utilizador atual.
    @return: Redireciona para a página inicial.
    """
    session.clear()
    return redirect(url_for("index"))


# ─── Páginas principais ──────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def index():
    """
    Página principal que gere a derivação de chaves atuais e passadas.
    @return: Renderiza o template inicial com resultados de chaves.
    """
    current_result = None
    past_result = None
    logged_in = "user_email" in session

    if request.method == "POST":
        form_type = request.form.get("form_type")
        email = request.form.get("email", "").strip()

        try:
            if form_type == "current_key":
                if not email:
                    raise ValueError("Tens de indicar um email.")
                current_result = derive_current_key(email)
                dt = datetime.strptime(current_result["timestamp"], "%Y-%m-%d %H:%M:%S")
                expires = dt + timedelta(minutes=1)
                current_result["period"] = f"{dt.strftime('%H:%M')} – {expires.strftime('%H:%M')}"
                current_result["expires_at"] = expires.strftime("%Y-%m-%dT%H:%M:%S")
                current_result["email"] = email
                session["last_current_result"] = current_result

            elif form_type == "past_key":
                if not logged_in:
                    raise ValueError("Tens de fazer login para aceder a chaves do passado.")
                past_datetime = request.form.get("past_datetime", "").strip()
                if not email or not past_datetime:
                    raise ValueError("Tens de indicar o email e a data/hora passada.")
                past_result = derive_past_key(email, past_datetime)
                session["last_past_result"] = past_result

        except Exception as exc:
            flash(f"Erro: {exc}", "error")

        return redirect(url_for("index"))

    else:
        last = session.get("last_current_result")
        if last:
            expires = datetime.strptime(last["expires_at"], "%Y-%m-%dT%H:%M:%S")
            if datetime.now() < expires:
                current_result = last
            else:
                session.pop("last_current_result", None)
        past_result = session.get("last_past_result") if logged_in else None

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return render_template(
        "index.html",
        current_result=current_result,
        past_result=past_result,
        logged_in=logged_in,
        now=now,
    )


@app.route("/encrypt", methods=["GET", "POST"])
@login_required
def encrypt_page():
    """
    Processa a cifra de ficheiros com chaves derivadas do futuro.
    @return: Response contendo o ficheiro cifrado (download).
    """
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

            signature = sign_package(
                private_key=load_private_key(),
                email=key_data["email"],
                timestamp=key_data["timestamp"],
                algorithm=aes_mode,
                hmac_algorithm=hmac_algorithm,
                original_filename=uploaded_file.filename,
                iv=encrypted_data["iv"],
                ciphertext=encrypted_data["ciphertext"],
                hmac_tag=hmac_tag,
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
                signature=signature,
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
    """
    Processa a decifra de ficheiros após validação de data, assinatura e integridade.
    @return: Response contendo o ficheiro decifrado (download).
    """
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

            signature_valid = verify_signature(
                public_key=load_public_key(),
                email=package["email"],
                timestamp=package["timestamp"],
                algorithm=package["algorithm"],
                hmac_algorithm=package["hmac_algorithm"],
                original_filename=package["original_filename"],
                iv=package["iv"],
                ciphertext=package["ciphertext"],
                hmac_tag=package["hmac"],
                signature_b64=package["signature"],
            )

            if not signature_valid:
                raise ValueError(
                    "Falha na verificação da assinatura digital RSA do sistema."
                )

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
    """
    Lista o histórico de ficheiros cifrados do utilizador.
    @return: Renderiza o template de histórico.
    """
    records = get_encrypted_files_by_email(session["user_email"])
    return render_template("history.html", records=records)


@app.route("/public-key")
@login_required
def public_key_page():
    """
    Disponibiliza a chave pública RSA do sistema para validação externa.
    @return: Response contendo a chave pública em formato PEM.
    """
    return Response(get_public_key_pem(), mimetype="text/plain")


if __name__ == "__main__":
    app.run(debug=True, port=5001, ssl_context=("ssl_cert.pem", "ssl_key.pem"))