import os
from functools import lru_cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from config import (
    KEYS_DIR,
    RSA_PRIVATE_KEY_PATH,
    RSA_PUBLIC_KEY_PATH,
    RSA_KEY_PASSPHRASE,
    RSA_KEY_SIZE,
)


def ensure_system_keypair() -> None:
    """
    Garante que o par de chaves RSA do sistema existe em disco.
    Gera um novo par caso não existam ficheiros nos caminhos configurados,
    protegendo a chave privada com a passphrase configurada.
    """
    os.makedirs(KEYS_DIR, exist_ok=True)

    if os.path.exists(RSA_PRIVATE_KEY_PATH) and os.path.exists(RSA_PUBLIC_KEY_PATH):
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            RSA_KEY_PASSPHRASE.encode("utf-8")
        ),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(RSA_PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_pem)
    with open(RSA_PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_pem)


@lru_cache(maxsize=1)
def load_private_key():
    """
    Carrega a chave privada RSA do sistema a partir do disco.
    Utiliza lru_cache para evitar leituras repetidas do ficheiro.
    @return: Objeto de chave privada carregado.
    """
    with open(RSA_PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=RSA_KEY_PASSPHRASE.encode("utf-8"),
        )


@lru_cache(maxsize=1)
def load_public_key():
    """
    Carrega a chave pública RSA do sistema a partir do disco.
    Utiliza lru_cache para eficiência.
    @return: Objeto de chave pública carregado.
    """
    with open(RSA_PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def get_public_key_pem() -> str:
    """
    Lê e devolve o conteúdo da chave pública em formato PEM.
    @return: String contendo a chave pública.
    """
    with open(RSA_PUBLIC_KEY_PATH, "r", encoding="utf-8") as f:
        return f.read()