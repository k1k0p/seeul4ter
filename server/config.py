import os
#Precisa de comentários

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SYSTEM_SECRET = "segredo-interno-do-sistema"

DATABASE_PATH = os.path.join(BASE_DIR, "..", "database", "seeul4ter.db")

STORAGE_DIR = os.path.join(BASE_DIR, "storage")
ENCRYPTED_DIR = os.path.join(STORAGE_DIR, "encrypted")
TEMP_DIR = os.path.join(STORAGE_DIR, "temp")