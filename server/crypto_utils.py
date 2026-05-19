import base64
import hashlib
import hmac
import json
import os
from datetime import datetime

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from config import SYSTEM_SECRET


def normalize_email(email: str) -> str:
    return email.strip().lower()


def get_current_hour_timestamp() -> str:
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:00:00")


def normalize_timestamp(timestamp_str: str) -> str:
    dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M")
    return dt.strftime("%Y-%m-%d %H:00:00")


def derive_keys(email: str, timestamp: str) -> dict:
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
    timestamp = get_current_hour_timestamp()
    return derive_keys(email, timestamp)


def derive_future_key(email: str, timestamp_str: str) -> dict:
    normalized_timestamp = normalize_timestamp(timestamp_str)
    return derive_keys(email, normalized_timestamp)


# ─── AES-128-CBC ────────────────────────────────────────────────────────────

def encrypt_file_aes_cbc(file_bytes: bytes, key_bytes: bytes) -> dict:
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return {"iv": iv, "ciphertext": ciphertext}


def decrypt_file_aes_cbc(ciphertext: bytes, key_bytes: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()


# ─── AES-128-CTR ────────────────────────────────────────────────────────────

def encrypt_file_aes_ctr(file_bytes: bytes, key_bytes: bytes) -> dict:
    # nonce de 16 bytes (usado como counter inicial no CTR)
    nonce = os.urandom(16)

    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_bytes) + encryptor.finalize()

    return {"iv": nonce, "ciphertext": ciphertext}


def decrypt_file_aes_ctr(ciphertext: bytes, key_bytes: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ─── Funções genéricas (despacham para CBC ou CTR) ──────────────────────────

def encrypt_file(file_bytes: bytes, key_bytes: bytes, aes_mode: str) -> dict:
    if aes_mode == "AES-128-CTR":
        return encrypt_file_aes_ctr(file_bytes, key_bytes)
    return encrypt_file_aes_cbc(file_bytes, key_bytes)


def decrypt_file(ciphertext: bytes, key_bytes: bytes, iv: bytes, aes_mode: str) -> bytes:
    if aes_mode == "AES-128-CTR":
        return decrypt_file_aes_ctr(ciphertext, key_bytes, iv)
    return decrypt_file_aes_cbc(ciphertext, key_bytes, iv)


# ─── HMAC ───────────────────────────────────────────────────────────────────

def _build_hmac_message(
    email: str,
    timestamp: str,
    algorithm: str,
    hmac_algorithm: str,
    original_filename: str,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:
    return (
        email.encode("utf-8")
        + timestamp.encode("utf-8")
        + algorithm.encode("utf-8")
        + hmac_algorithm.encode("utf-8")
        + original_filename.encode("utf-8")
        + iv
        + ciphertext
    )


def compute_hmac(
    hmac_key_bytes: bytes,
    email: str,
    timestamp: str,
    algorithm: str,
    hmac_algorithm: str,
    original_filename: str,
    iv: bytes,
    ciphertext: bytes,
) -> str:
    message = _build_hmac_message(
        email, timestamp, algorithm, hmac_algorithm, original_filename, iv, ciphertext
    )
    hash_fn = hashlib.sha512 if hmac_algorithm == "HMAC-SHA512" else hashlib.sha256
    return hmac.new(hmac_key_bytes, message, hash_fn).hexdigest()


def verify_hmac(
    hmac_key_bytes: bytes,
    email: str,
    timestamp: str,
    algorithm: str,
    hmac_algorithm: str,
    original_filename: str,
    iv: bytes,
    ciphertext: bytes,
    received_hmac: str,
) -> bool:
    expected = compute_hmac(
        hmac_key_bytes, email, timestamp, algorithm, hmac_algorithm,
        original_filename, iv, ciphertext,
    )
    return hmac.compare_digest(expected, received_hmac)


# Aliases para compatibilidade com código anterior
def compute_hmac_sha256(hmac_key_bytes, email, timestamp, algorithm, original_filename, iv, ciphertext):
    return compute_hmac(hmac_key_bytes, email, timestamp, algorithm, "HMAC-SHA256", original_filename, iv, ciphertext)

def verify_hmac_sha256(hmac_key_bytes, email, timestamp, algorithm, original_filename, iv, ciphertext, received_hmac):
    return verify_hmac(hmac_key_bytes, email, timestamp, algorithm, "HMAC-SHA256", original_filename, iv, ciphertext, received_hmac)


# ─── Pacote cifrado ─────────────────────────────────────────────────────────

def build_encrypted_package(
    email: str,
    timestamp: str,
    original_filename: str,
    aes_mode: str,
    hmac_algorithm: str,
    iv: bytes,
    ciphertext: bytes,
    hmac_tag: str,
) -> str:
    package = {
        "email": email,
        "timestamp": timestamp,
        "algorithm": aes_mode,
        "hmac_algorithm": hmac_algorithm,
        "original_filename": original_filename,
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "hmac": hmac_tag,
    }
    return json.dumps(package, indent=4)


def load_encrypted_package(json_bytes: bytes) -> dict:
    package = json.loads(json_bytes.decode("utf-8"))
    return {
        "email": package["email"],
        "timestamp": package["timestamp"],
        "algorithm": package["algorithm"],
        "hmac_algorithm": package.get("hmac_algorithm", "HMAC-SHA256"),
        "original_filename": package["original_filename"],
        "iv": base64.b64decode(package["iv"]),
        "ciphertext": base64.b64decode(package["ciphertext"]),
        "hmac": package["hmac"],
    }


# ─── Tempo ──────────────────────────────────────────────────────────────────

def get_current_server_time() -> datetime:
    return datetime.now()


def parse_package_timestamp(timestamp_str: str) -> datetime:
    return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")


def is_unlock_time_reached(timestamp_str: str) -> bool:
    target_time = parse_package_timestamp(timestamp_str)
    return datetime.now() >= target_time