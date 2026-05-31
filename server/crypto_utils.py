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
    """
    Normaliza o email removendo espaços em branco e convertendo para minúsculas.
    @param email: O email fornecido pelo utilizador.
    @return: O email normalizado.
    """
    return email.strip().lower()


def get_current_hour_timestamp() -> str:
    """
    Obtém o timestamp atual formatado até à hora, com minutos a zero.
    @return: String de timestamp no formato 'YYYY-MM-DD HH:MM:00'.
    """
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:00")   


def normalize_timestamp(timestamp_str: str) -> str:
    """
    Converte um timestamp de input (datetime-local) para o formato canónico do sistema.
    @param timestamp_str: String de data/hora (YYYY-MM-DDTHH:MM).
    @return: String formatada como 'YYYY-MM-DD HH:MM:00'.
    """
    dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M")
    return dt.strftime("%Y-%m-%d %H:%M:00")     


def derive_keys(email: str, timestamp: str) -> dict:
    """
    Deriva chaves AES e HMAC determinísticas a partir de um email, timestamp e segredo do sistema.
    @param email: Email do utilizador.
    @param timestamp: Momento temporal de referência.
    @return: Dicionário contendo chaves hexadecimais e bytes para AES e HMAC.
    """
    normalized_email = normalize_email(email)

    aes_material = f"AES|{normalized_email}|{SYSTEM_SECRET}|{timestamp}"
    aes_digest = hashlib.sha256(aes_material.encode("utf-8")).digest()
    aes_key_bytes = aes_digest[:16]

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
    """
    Deriva a chave para o intervalo horário atual.
    @param email: Email do utilizador.
    @return: Dicionário com as chaves derivadas.
    """
    timestamp = get_current_hour_timestamp()
    return derive_keys(email, timestamp)


def derive_future_key(email: str, timestamp_str: str) -> dict:
    """
    Deriva a chave para um instante futuro.
    @param email: Email do utilizador.
    @param timestamp_str: Timestamp futuro pretendido.
    @return: Dicionário com as chaves derivadas.
    """
    normalized_timestamp = normalize_timestamp(timestamp_str)
    return derive_keys(email, normalized_timestamp)


def derive_past_key(email: str, timestamp_str: str) -> dict:
    """
    Deriva a chave para um instante do passado.
    @param email: Email do utilizador.
    @param timestamp_str: Timestamp passado pretendido.
    @return: Dicionário com as chaves derivadas.
    @raise ValueError: Se o timestamp for futuro.
    """
    normalized_timestamp = normalize_timestamp(timestamp_str)
    target = datetime.strptime(normalized_timestamp, "%Y-%m-%d %H:%M:%S")

    if target > datetime.now():
        raise ValueError(
            "Só é possível obter chaves do passado ou do momento atual, nunca futuras."
        )

    return derive_keys(email, normalized_timestamp)


# ─── AES-128-CBC ────────────────────────────────────────────────────────────

def encrypt_file_aes_cbc(file_bytes: bytes, key_bytes: bytes) -> dict:
    """
    Cifra dados usando AES-128-CBC com preenchimento PKCS7.
    @param file_bytes: Conteúdo original do ficheiro.
    @param key_bytes: Chave AES de 16 bytes.
    @return: Dicionário com o IV e o texto cifrado.
    """
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return {"iv": iv, "ciphertext": ciphertext}


def decrypt_file_aes_cbc(ciphertext: bytes, key_bytes: bytes, iv: bytes) -> bytes:
    """
    Decifra dados cifrados com AES-128-CBC.
    @param ciphertext: Texto cifrado.
    @param key_bytes: Chave AES.
    @param iv: Vetor de inicialização utilizado.
    @return: Conteúdo original decifrado.
    """
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()


# ─── AES-128-CTR ────────────────────────────────────────────────────────────

def encrypt_file_aes_ctr(file_bytes: bytes, key_bytes: bytes) -> dict:
    """
    Cifra dados usando AES-128-CTR.
    @param file_bytes: Conteúdo original.
    @param key_bytes: Chave AES.
    @return: Dicionário com o nonce e o texto cifrado.
    """
    nonce = os.urandom(16)

    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_bytes) + encryptor.finalize()

    return {"iv": nonce, "ciphertext": ciphertext}


def decrypt_file_aes_ctr(ciphertext: bytes, key_bytes: bytes, iv: bytes) -> bytes:
    """
    Decifra dados cifrados com AES-128-CTR.
    @param ciphertext: Texto cifrado.
    @param key_bytes: Chave AES.
    @param iv: Nonce utilizado.
    @return: Conteúdo original.
    """
    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ─── Funções genéricas ──────────────────────────────────────────────────────

def encrypt_file(file_bytes: bytes, key_bytes: bytes, aes_mode: str) -> dict:
    """
    Despacha o processo de cifra para o modo AES solicitado.
    @param aes_mode: 'AES-128-CTR' ou 'AES-128-CBC'.
    """
    if aes_mode == "AES-128-CTR":
        return encrypt_file_aes_ctr(file_bytes, key_bytes)
    return encrypt_file_aes_cbc(file_bytes, key_bytes)


def decrypt_file(ciphertext: bytes, key_bytes: bytes, iv: bytes, aes_mode: str) -> bytes:
    """
    Despacha o processo de decifra para o modo AES solicitado.
    """
    if aes_mode == "AES-128-CTR":
        return decrypt_file_aes_ctr(ciphertext, key_bytes, iv)
    return decrypt_file_aes_cbc(ciphertext, key_bytes, iv)


# ─── HMAC ───────────────────────────────────────────────────────────────────

def _build_hmac_message(
    email: str, timestamp: str, algorithm: str, hmac_algorithm: str,
    original_filename: str, iv: bytes, ciphertext: bytes
) -> bytes:
    """Constrói a mensagem canónica para cálculo do HMAC."""
    return (
        email.encode("utf-8") + timestamp.encode("utf-8") + algorithm.encode("utf-8") +
        hmac_algorithm.encode("utf-8") + original_filename.encode("utf-8") + iv + ciphertext
    )


def compute_hmac(
    hmac_key_bytes: bytes, email: str, timestamp: str, algorithm: str,
    hmac_algorithm: str, original_filename: str, iv: bytes, ciphertext: bytes
) -> str:
    """Calcula o HMAC para verificar a integridade do ficheiro cifrado."""
    message = _build_hmac_message(
        email, timestamp, algorithm, hmac_algorithm, original_filename, iv, ciphertext
    )
    hash_fn = hashlib.sha512 if hmac_algorithm == "HMAC-SHA512" else hashlib.sha256
    return hmac.new(hmac_key_bytes, message, hash_fn).hexdigest()


def verify_hmac(
    hmac_key_bytes: bytes, email: str, timestamp: str, algorithm: str,
    hmac_algorithm: str, original_filename: str, iv: bytes, ciphertext: bytes, received_hmac: str
) -> bool:
    """Verifica a integridade via HMAC usando comparação em tempo constante."""
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
    """Constrói a mensagem a ser assinada digitalmente pelo sistema."""
    return (
        _build_hmac_message(
            email, timestamp, algorithm, hmac_algorithm, original_filename, iv, ciphertext
        ) + hmac_tag.encode("utf-8")
    )


def sign_package(
    private_key, email: str, timestamp: str, algorithm: str, hmac_algorithm: str,
    original_filename: str, iv: bytes, ciphertext: bytes, hmac_tag: str
) -> str:
    """Assina o pacote com a chave privada RSA usando PSS + SHA256."""
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
    """Verifica a assinatura digital RSA do sistema."""
    if not signature_b64: return False
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
        return False


# ─── Pacote cifrado ─────────────────────────────────────────────────────────

def build_encrypted_package(
    email: str, timestamp: str, original_filename: str, aes_mode: str,
    hmac_algorithm: str, iv: bytes, ciphertext: bytes, hmac_tag: str,
    signature: str = "", signature_algorithm: str = SIGNATURE_ALGORITHM
) -> str:
    """Serializa o pacote de dados cifrados para JSON."""
    package = {
        "email": email, "timestamp": timestamp, "algorithm": aes_mode,
        "hmac_algorithm": hmac_algorithm, "original_filename": original_filename,
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "hmac": hmac_tag, "signature": signature, "signature_algorithm": signature_algorithm,
    }
    return json.dumps(package, indent=4)


def load_encrypted_package(json_bytes: bytes) -> dict:
    """Carrega e deserializa um pacote cifrado a partir de JSON."""
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
    """Verifica se a data/hora de desbloqueio do ficheiro já foi atingida."""
    target_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    return datetime.now() >= target_time