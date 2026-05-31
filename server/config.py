"""
Configuração central da aplicação.

Reúne caminhos, segredos e parâmetros usados em todo o sistema. Os valores
sensíveis (segredo de derivação, chave de sessão, passphrase RSA) são lidos de
variáveis de ambiente, com fallbacks apenas para desenvolvimento local.
"""

import os

# Pasta base do backend
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ─── Segredos ────────────────────────────────────────────────────────────────
# IMPORTANTE: em "produção" estes valores devem vir SEMPRE do ambiente.
# Os fallbacks existem apenas para facilitar o desenvolvimento local e NÃO
# devem ser usados num sistema real (o SYSTEM_SECRET é a raiz de confiança de
# todas as chaves temporais; se vazar, todas as cápsulas ficam comprometidas).

# Segredo interno usado na derivação das chaves temporais.
# É a peça mais sensível do sistema: entra em todas as chaves AES e HMAC.
SYSTEM_SECRET = os.environ.get("SEEUL4TER_SECRET", "segredo-interno-do-sistema")

# Chave de sessão do Flask (assina os cookies de sessão). Se for previsível,
# um atacante poderia forjar sessões de outros utilizadores.
FLASK_SECRET_KEY = os.environ.get("SEEUL4TER_FLASK_SECRET", "chave-secreta-da-sessao-flask")

# Caminho da base de dados SQLite (uma pasta acima do backend).
DATABASE_PATH = os.path.join(BASE_DIR, "..", "database", "seeul4ter.db")

# Pastas auxiliares para armazenamento, caso sejam usadas mais tarde.
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
ENCRYPTED_DIR = os.path.join(STORAGE_DIR, "encrypted")
TEMP_DIR = os.path.join(STORAGE_DIR, "temp")

# ─── Chaves RSA do sistema (para assinatura digital) ─────────────────────────
# O sistema mantém um par de chaves RSA próprio. Assina cada pacote cifrado com
# a chave privada e verifica essa assinatura na decifra com a chave pública.
KEYS_DIR = os.path.join(BASE_DIR, "keys")
RSA_PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "system_private.pem")
RSA_PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "system_public.pem")

# Passphrase que protege a chave privada do sistema em disco (cifra o PEM).
RSA_KEY_PASSPHRASE = os.environ.get(
    "SEEUL4TER_RSA_PASSPHRASE", "passphrase-da-chave-rsa-do-sistema"
)

# Tamanho do módulo RSA. 2048 bits é o mínimo recomendado atualmente.
RSA_KEY_SIZE = 2048