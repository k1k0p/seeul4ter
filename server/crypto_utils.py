"""
Núcleo criptográfico do SEE-U-L4TER.

Reúne toda a lógica de criptografia do sistema:

- Derivação determinística de chaves AES e HMAC a partir de (email, data-hora,
  segredo do servidor). Como a chave depende da data-hora, o instante de
  desbloqueio fica criptograficamente ligado à própria chave.
- Cifra/decifra simétrica com AES-128 em modo CBC ou CTR.
- Integridade e autenticidade via HMAC (Encrypt-then-MAC).
- Assinatura digital RSA do sistema (RSA-PSS + SHA-256).
- Serialização do pacote cifrado em JSON e verificação temporal.
"""

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from config import SYSTEM_SECRET

SIGNATURE_ALGORITHM = "RSA-PSS-SHA256"


def normalize_email(email: str) -> str:
    """Normaliza o email (remove espaços e passa a minúsculas).

    É essencial que a normalização seja idêntica em todo o lado: como o email
    entra na derivação da chave, "A@x.com" e "a@x.com " têm de produzir a mesma
    chave, senão um ficheiro cifrado nunca mais seria decifrável.

    Args:
        email: o email fornecido pelo utilizador.

    Returns:
        O email normalizado.
    """
    return email.strip().lower()


def get_current_hour_timestamp() -> str:
    """Devolve o timestamp do minuto atual, com segundos a zero.

    A granularidade é ao minuto (HH:MM:00): a chave do momento atual é válida
    durante o minuto corrente. Os segundos são fixados a zero para que todas as
    derivações dentro do mesmo minuto produzam a mesma chave.

    Returns:
        String no formato 'YYYY-MM-DD HH:MM:00'.
    """
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:00")


def normalize_timestamp(timestamp_str: str) -> str:
    """Converte a data/hora do formulário para o formato canónico do sistema.

    O input vem de um campo datetime-local (YYYY-MM-DDTHH:MM, sem segundos).
    Fixa os segundos a zero, garantindo que o timestamp usado na cifra coincide
    exatamente com o usado na derivação da chave.

    Args:
        timestamp_str: data/hora no formato 'YYYY-MM-DDTHH:MM'.

    Returns:
        String no formato 'YYYY-MM-DD HH:MM:00'.
    """
    dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M")
    return dt.strftime("%Y-%m-%d %H:%M:00")


def derive_keys(email: str, timestamp: str) -> dict:
    """Deriva as chaves AES e HMAC de forma determinística.

    Cada chave resulta do hash SHA-256 de uma string que combina um rótulo de
    domínio ("AES" ou "HMAC"), o email, o segredo do servidor e a data-hora:

        chave AES  = SHA256("AES|email|SEGREDO|data-hora")[:16]   (AES-128)
        chave HMAC = SHA256("HMAC|email|SEGREDO|data-hora")

    Os rótulos diferentes ("AES" vs "HMAC") fazem separação de domínio: garantem
    que a chave de cifra e a de integridade são distintas, mesmo derivando do
    mesmo segredo e dos mesmos dados. A dependência da data-hora é o que liga a
    chave ao instante de desbloqueio.

    Args:
        email: email do utilizador.
        timestamp: instante de referência (formato canónico).

    Returns:
        Dicionário com as chaves em hexadecimal e em bytes, mais email e timestamp.
    """
    normalized_email = normalize_email(email)

    # Chave de cifra: 16 bytes (128 bits) tirados do início do digest SHA-256.
    aes_material = f"AES|{normalized_email}|{SYSTEM_SECRET}|{timestamp}"
    aes_digest = hashlib.sha256(aes_material.encode("utf-8")).digest()
    aes_key_bytes = aes_digest[:16]

    # Chave de integridade: digest completo, com rótulo "HMAC" para a separar
    # da chave de cifra (separação de domínio).
    hmac_material = f"HMAC|{normalized_email}|{SYSTEM_SECRET}|{timestamp}"
    hmac_digest = hashlib.sha256(hmac_material.encode("utf-8")).digest()

    return {
        "email": normalized_email,
        "timestamp": timestamp,
        "aes_key_hex": aes_key_bytes.hex(),
        "aes_key_bytes": aes_key_bytes,
        "hmac_key_hex": hmac_digest.hex(),
        "hmac_key_bytes": hmac_digest,
    }


def derive_current_key(email: str) -> dict:
    """Deriva a chave correspondente ao minuto atual.

    Args:
        email: email do utilizador.

    Returns:
        Dicionário com as chaves derivadas (ver derive_keys).
    """
    timestamp = get_current_hour_timestamp()
    return derive_keys(email, timestamp)


def derive_future_key(email: str, timestamp_str: str) -> dict:
    """Deriva a chave para um instante futuro (usada apenas na cifra).

    Atenção: esta chave é calculada no servidor para cifrar o ficheiro e NUNCA
    deve ser devolvida ao utilizador para datas futuras — caso contrário a
    cápsula poderia ser aberta antes do tempo. A interface não expõe esta função.

    Args:
        email: email do utilizador.
        timestamp_str: data/hora futura (formato do formulário).

    Returns:
        Dicionário com as chaves derivadas.
    """
    normalized_timestamp = normalize_timestamp(timestamp_str)
    return derive_keys(email, normalized_timestamp)


def derive_past_key(email: str, timestamp_str: str) -> dict:
    """Deriva a chave para um instante já decorrido (ou o momento atual).

    É a função exposta a utilizadores registados (enhancement #5): podem
    recuperar chaves do passado, mas a função recusa explicitamente qualquer
    data futura. É esta recusa que mantém fechadas as cápsulas ainda por abrir.

    Args:
        email: email do utilizador.
        timestamp_str: data/hora pretendida (formato do formulário).

    Returns:
        Dicionário com as chaves derivadas.

    Raises:
        ValueError: se o timestamp pedido for futuro.
    """
    normalized_timestamp = normalize_timestamp(timestamp_str)
    target = datetime.strptime(normalized_timestamp, "%Y-%m-%d %H:%M:%S")

    # Barreira de segurança: nunca revelar chaves de datas que ainda não chegaram.
    if target > datetime.now():
        raise ValueError(
            "Só é possível obter chaves do passado ou do momento atual, nunca futuras."
        )

    return derive_keys(email, normalized_timestamp)


# ─── AES-128-CBC ────────────────────────────────────────────────────────────

def encrypt_file_aes_cbc(file_bytes: bytes, key_bytes: bytes) -> dict:
    """Cifra dados com AES-128 em modo CBC, com padding PKCS7.

    Gera um IV aleatório de 16 bytes a cada cifra (essencial: reutilizar IV com
    a mesma chave em CBC compromete a confidencialidade). O CBC exige que os
    dados sejam múltiplos do tamanho do bloco, daí o padding PKCS7.

    Args:
        file_bytes: conteúdo original.
        key_bytes: chave AES de 16 bytes.

    Returns:
        Dicionário com o IV e o ciphertext (bytes).
    """
    iv = os.urandom(16)  # IV novo e aleatório por operação

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return {"iv": iv, "ciphertext": ciphertext}


def decrypt_file_aes_cbc(ciphertext: bytes, key_bytes: bytes, iv: bytes) -> bytes:
    """Decifra dados cifrados com AES-128-CBC e remove o padding PKCS7.

    Args:
        ciphertext: texto cifrado.
        key_bytes: chave AES.
        iv: o mesmo IV usado na cifra.

    Returns:
        O conteúdo original em bytes.
    """
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()


# ─── AES-128-CTR ────────────────────────────────────────────────────────────

def encrypt_file_aes_ctr(file_bytes: bytes, key_bytes: bytes) -> dict:
    """Cifra dados com AES-128 em modo CTR.

    O CTR transforma a cifra de blocos numa cifra de fluxo, pelo que não precisa
    de padding. Gera um nonce aleatório de 16 bytes que funciona como contador
    inicial. Tal como o IV no CBC, este nonce NUNCA pode repetir-se com a mesma
    chave: a reutilização expõe o XOR dos textos em claro.

    Args:
        file_bytes: conteúdo original.
        key_bytes: chave AES.

    Returns:
        Dicionário com o nonce (em "iv") e o ciphertext.
    """
    nonce = os.urandom(16)  # contador inicial, único por operação

    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_bytes) + encryptor.finalize()

    return {"iv": nonce, "ciphertext": ciphertext}


def decrypt_file_aes_ctr(ciphertext: bytes, key_bytes: bytes, iv: bytes) -> bytes:
    """Decifra dados cifrados com AES-128-CTR.

    Args:
        ciphertext: texto cifrado.
        key_bytes: chave AES.
        iv: o mesmo nonce usado na cifra.

    Returns:
        O conteúdo original em bytes.
    """
    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ─── Funções genéricas ──────────────────────────────────────────────────────

def encrypt_file(file_bytes: bytes, key_bytes: bytes, aes_mode: str) -> dict:
    """Cifra um ficheiro, despachando para o modo AES pedido.

    Args:
        file_bytes: conteúdo original.
        key_bytes: chave AES.
        aes_mode: "AES-128-CTR" ou "AES-128-CBC" (CBC é o predefinido).

    Returns:
        Dicionário com IV/nonce e ciphertext.
    """
    if aes_mode == "AES-128-CTR":
        return encrypt_file_aes_ctr(file_bytes, key_bytes)
    return encrypt_file_aes_cbc(file_bytes, key_bytes)


def decrypt_file(ciphertext: bytes, key_bytes: bytes, iv: bytes, aes_mode: str) -> bytes:
    """Decifra um ficheiro, despachando para o modo AES pedido.

    Args:
        ciphertext: texto cifrado.
        key_bytes: chave AES.
        iv: IV (CBC) ou nonce (CTR) usado na cifra.
        aes_mode: "AES-128-CTR" ou "AES-128-CBC".

    Returns:
        O conteúdo original em bytes.
    """
    if aes_mode == "AES-128-CTR":
        return decrypt_file_aes_ctr(ciphertext, key_bytes, iv)
    return decrypt_file_aes_cbc(ciphertext, key_bytes, iv)


# ─── HMAC ───────────────────────────────────────────────────────────────────

def _build_hmac_message(
    email: str, timestamp: str, algorithm: str, hmac_algorithm: str,
    original_filename: str, iv: bytes, ciphertext: bytes
) -> bytes:
    """Constrói a mensagem canónica sobre a qual se calcula o HMAC.

    Inclui todos os metadados além do criptograma, de modo a que o HMAC proteja
    não só o conteúdo cifrado mas também o email, o timestamp, os algoritmos, o
    nome do ficheiro e o IV. Assim, alterar qualquer um destes campos invalida
    o HMAC.
    """
    return (
        email.encode("utf-8") + timestamp.encode("utf-8") + algorithm.encode("utf-8") +
        hmac_algorithm.encode("utf-8") + original_filename.encode("utf-8") + iv + ciphertext
    )


def compute_hmac(
    hmac_key_bytes: bytes, email: str, timestamp: str, algorithm: str,
    hmac_algorithm: str, original_filename: str, iv: bytes, ciphertext: bytes
) -> str:
    """Calcula o HMAC (SHA-256 ou SHA-512) do pacote.

    Segue o padrão Encrypt-then-MAC: o HMAC é calculado sobre o texto já cifrado
    (mais os metadados), o que permite verificar a integridade antes de tentar
    decifrar.

    Returns:
        O HMAC em hexadecimal.
    """
    message = _build_hmac_message(
        email, timestamp, algorithm, hmac_algorithm, original_filename, iv, ciphertext
    )
    hash_fn = hashlib.sha512 if hmac_algorithm == "HMAC-SHA512" else hashlib.sha256
    return hmac.new(hmac_key_bytes, message, hash_fn).hexdigest()


def verify_hmac(
    hmac_key_bytes: bytes, email: str, timestamp: str, algorithm: str,
    hmac_algorithm: str, original_filename: str, iv: bytes, ciphertext: bytes, received_hmac: str
) -> bool:
    """Verifica o HMAC recebido recalculando-o e comparando.

    Usa hmac.compare_digest, que compara em tempo constante: o tempo de resposta
    não depende de quantos caracteres coincidem, evitando ataques de temporização.

    Returns:
        True se o HMAC for válido, False caso contrário.
    """
    expected = compute_hmac(
        hmac_key_bytes, email, timestamp, algorithm, hmac_algorithm,
        original_filename, iv, ciphertext,
    )
    return hmac.compare_digest(expected, received_hmac)


# ─── Assinatura digital RSA ──────────────────────────────────────────────────

def _build_signature_message(
    email: str, timestamp: str, algorithm: str, hmac_algorithm: str,
    original_filename: str, iv: bytes, ciphertext: bytes, hmac_tag: str
) -> bytes:
    """Constrói a mensagem assinada pelo sistema.

    Reutiliza a mensagem do HMAC e acrescenta a própria tag HMAC, para que a
    assinatura cubra simultaneamente os metadados, o criptograma e o HMAC.
    """
    return (
        _build_hmac_message(
            email, timestamp, algorithm, hmac_algorithm, original_filename, iv, ciphertext
        ) + hmac_tag.encode("utf-8")
    )


def sign_package(
    private_key, email: str, timestamp: str, algorithm: str, hmac_algorithm: str,
    original_filename: str, iv: bytes, ciphertext: bytes, hmac_tag: str
) -> str:
    """Assina o pacote com a chave privada RSA do sistema.

    Usa o esquema RSA-PSS com SHA-256. O PSS é probabilístico (inclui salt),
    sendo o esquema de assinatura RSA recomendado atualmente, mais robusto que
    o antigo PKCS#1 v1.5.

    Returns:
        A assinatura codificada em Base64.
    """
    message = _build_signature_message(
        email, timestamp, algorithm, hmac_algorithm, original_filename, iv, ciphertext, hmac_tag
    )
    signature = private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(
    public_key, email: str, timestamp: str, algorithm: str, hmac_algorithm: str,
    original_filename: str, iv: bytes, ciphertext: bytes, hmac_tag: str, signature_b64: str
) -> bool:
    """Verifica a assinatura RSA do sistema com a chave pública.

    Reconstrói a mensagem assinada e valida a assinatura. Qualquer alteração aos
    metadados, ao criptograma ou ao HMAC faz a verificação falhar. Uma assinatura
    em falta ou inválida resulta em False (a função nunca lança exceção para fora).

    Returns:
        True se a assinatura for válida, False caso contrário.
    """
    if not signature_b64:
        return False
    message = _build_signature_message(
        email, timestamp, algorithm, hmac_algorithm, original_filename, iv, ciphertext, hmac_tag
    )
    try:
        public_key.verify(
            base64.b64decode(signature_b64), message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError):
        # Assinatura inválida ou Base64 malformado: tratado como falha de verificação.
        return False


# ─── Pacote cifrado ─────────────────────────────────────────────────────────

def build_encrypted_package(
    email: str, timestamp: str, original_filename: str, aes_mode: str,
    hmac_algorithm: str, iv: bytes, ciphertext: bytes, hmac_tag: str,
    signature: str = "", signature_algorithm: str = SIGNATURE_ALGORITHM
) -> str:
    """Serializa o pacote cifrado para JSON.

    Os campos binários (IV e ciphertext) são codificados em Base64 para poderem
    ser representados em texto. O pacote reúne tudo o que a decifra precisa:
    metadados, IV, ciphertext, HMAC e assinatura. Note-se que a chave NUNCA é
    incluída.

    Returns:
        O pacote como string JSON formatada.
    """
    package = {
        "email": email, "timestamp": timestamp, "algorithm": aes_mode,
        "hmac_algorithm": hmac_algorithm, "original_filename": original_filename,
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "hmac": hmac_tag, "signature": signature, "signature_algorithm": signature_algorithm,
    }
    return json.dumps(package, indent=4)


def load_encrypted_package(json_bytes: bytes) -> dict:
    """Carrega um pacote cifrado a partir de JSON.

    Descodifica os campos Base64 (IV e ciphertext) de volta para bytes. Usa
    valores predefinidos para campos opcionais (hmac_algorithm, signature),
    o que mantém compatibilidade com pacotes mais antigos.

    Returns:
        Dicionário com os campos do pacote prontos a usar.
    """
    package = json.loads(json_bytes.decode("utf-8"))
    return {
        "email": package["email"], "timestamp": package["timestamp"],
        "algorithm": package["algorithm"], "hmac_algorithm": package.get("hmac_algorithm", "HMAC-SHA256"),
        "original_filename": package["original_filename"],
        "iv": base64.b64decode(package["iv"]),
        "ciphertext": base64.b64decode(package["ciphertext"]),
        "hmac": package["hmac"], "signature": package.get("signature", ""),
        "signature_algorithm": package.get("signature_algorithm", SIGNATURE_ALGORITHM),
    }


# ─── Tempo ──────────────────────────────────────────────────────────────────

def is_unlock_time_reached(timestamp_str: str) -> bool:
    """Verifica se o instante de desbloqueio já chegou.

    Compara a data-hora alvo do pacote com a hora atual do servidor. É a primeira
    barreira da decifra: se ainda não chegou o momento, o ficheiro não é processado.

    Args:
        timestamp_str: data-hora de desbloqueio (formato canónico).

    Returns:
        True se a hora atual for igual ou posterior à data-hora alvo.
    """
    target_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    return datetime.now() >= target_time