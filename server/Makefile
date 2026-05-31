# Makefile — pasta server/
# Automação de instalação e execução do SEE-U-L4TER.

.PHONY: install run certs clean

# Instala as dependências a partir do requirements.txt na mesma pasta.
install:
	pip3 install -r requirements.txt

# Gera o certificado TLS auto-assinado, apenas se ainda não existir.
# É usado pelo app.py para servir a aplicação sobre HTTPS (localhost).
certs:
	@test -f ssl_cert.pem || openssl req -x509 -newkey rsa:2048 -nodes \
		-keyout ssl_key.pem -out ssl_cert.pem -days 365 -subj "/CN=localhost"

# Corre a aplicação. Garante primeiro que o certificado existe (alvo certs),
# evitando que o arranque falhe numa máquina onde os .pem ainda não foram gerados.
run: certs
	python3 app.py

# Remove ficheiros temporários do Python (cache de compilação).
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete