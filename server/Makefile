# Makefile dentro da pasta server/

.PHONY: install run clean

# Instala as dependências a partir do ficheiro na mesma pasta
install:
	pip install -r requirements.txt

# Corre a aplicação
run:
	python app.py

# Limpeza simples de ficheiros de compilação
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +