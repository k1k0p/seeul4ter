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


def encrypt_file_aes_cbc(file_bytes: bytes, key_bytes: bytes) -> dict:
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return {
        "iv": iv,
        "ciphertext": ciphertext,
    }


def decrypt_file_aes_cbc(ciphertext: bytes, key_bytes: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


def compute_hmac_sha256(
    hmac_key_bytes: bytes,
    email: str,
    timestamp: str,
    algorithm: str,
    original_filename: str,
    iv: bytes,
    ciphertext: bytes,
) -> str:
    message = (
        email.encode("utf-8")
        + timestamp.encode("utf-8")
        + algorithm.encode("utf-8")
        + original_filename.encode("utf-8")
        + iv
        + ciphertext
    )

    return hmac.new(hmac_key_bytes, message, hashlib.sha256).hexdigest()


def verify_hmac_sha256(
    hmac_key_bytes: bytes,
    email: str,
    timestamp: str,
    algorithm: str,
    original_filename: str,
    iv: bytes,
    ciphertext: bytes,
    received_hmac: str,
) -> bool:
    expected_hmac = compute_hmac_sha256(
        hmac_key_bytes=hmac_key_bytes,
        email=email,
        timestamp=timestamp,
        algorithm=algorithm,
        original_filename=original_filename,
        iv=iv,
        ciphertext=ciphertext,
    )

    return hmac.compare_digest(expected_hmac, received_hmac)


def build_encrypted_package(
    email: str,
    timestamp: str,
    original_filename: str,
    iv: bytes,
    ciphertext: bytes,
    hmac_tag: str,
) -> str:
    package = {
        "email": email,
        "timestamp": timestamp,
        "algorithm": "AES-128-CBC",
        "hmac_algorithm": "HMAC-SHA256",
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
        "hmac_algorithm": package["hmac_algorithm"],
        "original_filename": package["original_filename"],
        "iv": base64.b64decode(package["iv"]),
        "ciphertext": base64.b64decode(package["ciphertext"]),
        "hmac": package["hmac"],
    }


def get_current_server_time() -> datetime:
    return datetime.now()


def parse_package_timestamp(timestamp_str: str) -> datetime:
    return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")


def is_unlock_time_reached(timestamp_str: str) -> bool:
    target_time = parse_package_timestamp(timestamp_str)
    current_time = get_current_server_time()
    return current_time >= target_time