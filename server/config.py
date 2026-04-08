import os

# Pasta base do backend
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Segredo interno usado na derivação das chaves temporais
SYSTEM_SECRET = "segredo-interno-do-sistema"

# Caminho da base de dados SQLite
DATABASE_PATH = os.path.join(BASE_DIR, "..", "database", "seeul4ter.db")

# Pastas auxiliares para armazenamento, caso sejam usadas mais tarde
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
ENCRYPTED_DIR = os.path.join(STORAGE_DIR, "encrypted")
TEMP_DIR = os.path.join(STORAGE_DIR, "temp")