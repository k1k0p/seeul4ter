"""
SEE-U-L4TER — Cápsula do Tempo Criptográfica.

Aplicação web (Flask) que cifra ficheiros de forma a que só possam ser
decifrados a partir de uma data/hora futura. A chave de cifra é derivada de
forma determinística a partir de (email, data-hora, segredo do servidor), pelo
que o instante de desbloqueio fica criptograficamente ligado à própria chave.

Cada pacote cifrado é protegido por um HMAC (integridade) e por uma assinatura
digital RSA do sistema (autenticidade), ambos verificados antes da decifra.
"""

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

# Chave usada pelo Flask para assinar os cookies de sessão. Vem da configuração
# (idealmente de uma variável de ambiente) e nunca deve ser fixa em produção,
# caso contrário seria possível forjar sessões de utilizadores.
app.secret_key = FLASK_SECRET_KEY

init_db()                # cria as tabelas da base de dados, se ainda não existirem
ensure_system_keypair()  # gera o par RSA do sistema na primeira execução


# ─── Autenticação ────────────────────────────────────────────────────────────

def login_required(f):
    """Decorador que restringe uma rota a utilizadores autenticados.

    Verifica se existe um email na sessão; caso contrário, redireciona o
    utilizador para a página de login antes de a rota ser executada.

    Args:
        f: a função-rota a proteger.

    Returns:
        A função decorada, que só executa a rota original se houver sessão ativa.
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # A sessão do Flask é assinada (não cifrada); confiamos nela apenas
        # porque a secret_key impede que seja forjada do lado do cliente.
        if "user_email" not in session:
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


@app.route("/register", methods=["GET", "POST"])
def register_page():
    """Regista um novo utilizador.

    Em GET mostra o formulário; em POST valida os campos e tenta criar a conta,
    redirecionando para o login em caso de sucesso.

    Returns:
        O template de registo (com erro) ou um redirect para a página de login.
    """
    error = None
    if request.method == "POST":
        # O email é normalizado (sem espaços, em minúsculas) porque é usado na
        # derivação das chaves — tem de ser idêntico aqui e na cifra/decifra.
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        if not email or not password:
            error = "Preenche o email e a password."
        else:
            # register_user guarda a password como hash + salt, nunca em claro.
            ok, msg = register_user(email, password)
            if ok:
                flash("Conta criada com sucesso! Faz login.", "success")
                return redirect(url_for("login_page"))
            else:
                error = msg
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login_page():
    """Autentica um utilizador existente.

    Em POST verifica as credenciais e, se forem válidas, guarda o email na
    sessão. A mensagem de erro é deliberadamente genérica (não revela se foi
    o email ou a password que falhou) para não facilitar a enumeração de contas.

    Returns:
        Um redirect para a página inicial em caso de sucesso, ou o template de
        login com mensagem de erro em caso de falha.
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
    """Termina a sessão do utilizador.

    Returns:
        Um redirect para a página inicial (que é pública).
    """
    session.clear()  # remove todos os dados de sessão, incluindo o email
    return redirect(url_for("index"))


# ─── Páginas principais ──────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def index():
    """Página inicial: derivação da chave atual e de chaves passadas.

    A chave do momento atual está disponível a qualquer visitante (interface
    não autenticada, como pede o enunciado). O acesso a chaves de datas já
    decorridas exige sessão iniciada. Chaves de datas futuras nunca são
    reveladas aqui — caso contrário a cápsula podia ser aberta antes do tempo.

    Returns:
        O template inicial, com a chave atual e/ou a chave passada quando aplicável.
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
                # A chave atual só é válida durante o minuto corrente; guardamos
                # o instante de expiração para a deixar de mostrar depois disso.
                dt = datetime.strptime(current_result["timestamp"], "%Y-%m-%d %H:%M:%S")
                expires = dt + timedelta(minutes=1)
                current_result["period"] = f"{dt.strftime('%H:%M')} – {expires.strftime('%H:%M')}"
                current_result["expires_at"] = expires.strftime("%Y-%m-%dT%H:%M:%S")
                current_result["email"] = email
                session["last_current_result"] = current_result

            elif form_type == "past_key":
                # Enhancement #5: utilizadores registados acedem a chaves do
                # passado. derive_past_key recusa explicitamente datas futuras.
                if not logged_in:
                    raise ValueError("Tens de fazer login para aceder a chaves do passado.")
                past_datetime = request.form.get("past_datetime", "").strip()
                if not email or not past_datetime:
                    raise ValueError("Tens de indicar o email e a data/hora passada.")
                past_result = derive_past_key(email, past_datetime)
                session["last_past_result"] = past_result

        except Exception as exc:
            flash(f"Erro: {exc}", "error")

        # Padrão Post/Redirect/Get: redireciona após o POST para evitar que o
        # reenvio do formulário (refresh) repita a operação.
        return redirect(url_for("index"))

    else:
        # Em GET, recupera a última chave atual guardada em sessão, mas só a
        # mostra se ainda estiver dentro da janela de validade (1 minuto).
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
    """Cifra um ficheiro para uma data/hora futura.

    Deriva internamente a chave da data futura (nunca a devolve ao utilizador),
    cifra o ficheiro, calcula o HMAC, assina o conjunto com a chave privada RSA
    do sistema e devolve um pacote JSON com todos os metadados necessários à
    decifra posterior. Regista também a operação no histórico.

    Returns:
        Uma Response com o pacote cifrado (.encrypted.json) como download, ou o
        template de cifra com erro se algo falhar.
    """
    error = None

    if request.method == "POST":
        try:
            email = request.form.get("email", "").strip()
            future_datetime = request.form.get("future_datetime", "").strip()
            uploaded_file = request.files.get("file")
            aes_mode = request.form.get("aes_mode", "AES-128-CBC")
            hmac_algorithm = request.form.get("hmac_mode", "HMAC-SHA256")

            # Validação dos modos: só aceitamos valores conhecidos, evitando que
            # um valor arbitrário vindo do formulário chegue às funções de cifra.
            if aes_mode not in ("AES-128-CBC", "AES-128-CTR"):
                aes_mode = "AES-128-CBC"
            if hmac_algorithm not in ("HMAC-SHA256", "HMAC-SHA512"):
                hmac_algorithm = "HMAC-SHA256"

            if not email or not future_datetime or not uploaded_file:
                raise ValueError("Preenche o email, a data/hora e escolhe um ficheiro.")

            # A chave futura é derivada APENAS aqui, do lado do servidor, e nunca
            # é incluída no pacote nem mostrada — é o que mantém a cápsula fechada.
            key_data = derive_future_key(email, future_datetime)
            file_bytes = uploaded_file.read()

            if not file_bytes:
                raise ValueError("O ficheiro selecionado está vazio.")

            encrypted_data = encrypt_file(file_bytes, key_data["aes_key_bytes"], aes_mode)

            # HMAC sobre os metadados + IV + ciphertext (Encrypt-then-MAC):
            # garante integridade e autenticidade do criptograma.
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

            # Assinatura digital RSA do sistema (enhancement #3): prova que o
            # pacote foi produzido por este servidor e não foi adulterado.
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

            # Guarda apenas metadados da operação no histórico (nunca a chave
            # nem o conteúdo do ficheiro).
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
    """Decifra um ficheiro, após quatro verificações de segurança.

    Pela ordem: (1) o instante de desbloqueio já foi atingido; (2) a assinatura
    RSA do sistema é válida; (3) o HMAC confirma a integridade; (4) a chave AES
    fornecida corresponde à que se deriva do (email, data-hora) do pacote. Só se
    as quatro passarem é que o ficheiro é decifrado.

    Returns:
        Uma Response com o ficheiro original como download, ou o template de
        decifra com erro se alguma verificação falhar.
    """
    error = None

    if request.method == "POST":
        try:
            key_hex = request.form.get("key_hex", "").strip()
            uploaded_file = request.files.get("file")

            if not key_hex or not uploaded_file:
                raise ValueError("Fornece a chave AES e o ficheiro cifrado.")

            package = load_encrypted_package(uploaded_file.read())

            # 1. Verificação temporal: recusa a decifra antes da data/hora.
            if not is_unlock_time_reached(package["timestamp"]):
                raise ValueError(
                    f"O ficheiro só pode ser decifrado a partir de {package['timestamp']}."
                )

            # Reconstrói as chaves (AES e HMAC) a partir do email e timestamp do
            # pacote — não vêm no ficheiro, são derivadas com o segredo do servidor.
            key_data = derive_keys(package["email"], package["timestamp"])

            # 2. Assinatura RSA do sistema, verificada antes de qualquer decifra.
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

            # 3. Integridade via HMAC (comparação em tempo constante na função).
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

            # 4. A chave fornecida tem de coincidir com a chave derivada. Isto
            # confirma que o utilizador tem a chave certa para aquele instante.
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
    """Mostra o histórico de cifras do utilizador autenticado.

    Filtra os registos pelo email da sessão, para que cada utilizador veja
    apenas as suas operações e não as de terceiros.

    Returns:
        O template de histórico com os registos do utilizador.
    """
    records = get_encrypted_files_by_email(session["user_email"])
    return render_template("history.html", records=records)


@app.route("/public-key")
@login_required
def public_key_page():
    """Disponibiliza a chave pública RSA do sistema (PEM).

    Permite que as assinaturas dos pacotes sejam verificadas externamente
    (por exemplo, com o openssl). Só a chave pública é exposta; a privada
    permanece no servidor.

    Returns:
        Uma Response de texto com a chave pública em formato PEM.
    """
    return Response(get_public_key_pem(), mimetype="text/plain")


if __name__ == "__main__":
    # debug=True e o servidor embutido destinam-se apenas a desenvolvimento.
    # ssl_context ativa HTTPS com um certificado auto-assinado, cifrando o canal
    # entre o browser e o servidor (passwords, chaves e ficheiros não viajam em claro).
    app.run(debug=True, port=5001, ssl_context=("ssl_cert.pem", "ssl_key.pem"))