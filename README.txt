============================================================
PROJETO: SEE-U-L4TER
Trabalho 5 - Sistemas de Informação
============================================================

AUTORES:
- Davide Cravo
- Dinis Gonçalves
- Diogo Baltazar
- Francisco Pandeirada
- Gabriel Costa

DESCRIÇÃO:
Aplicação web para cifra e decifra temporizada de ficheiros. 
O sistema garante a integridade dos dados através de HMAC 
e a autenticidade via assinatura digital RSA (chave do sistema).

ESTRUTURA DO PROJETO:
/server           - Código fonte (Flask, lógica de cifra, DB, chaves)
/requirements.txt - Dependências necessárias para a execução
/Makefile         - Automação de tarefas (instalação e execução)

PRÉ-REQUISITOS:
- Python 3.10 ou superior
- Pip (gestor de pacotes Python)

COMO EXECUTAR:

1. Navegar para a pasta do servidor:
   $ cd server

2. Criar e ativar um ambiente virtual:
   - macOS / Linux:
     $ python3 -m venv venv
     $ source venv/bin/activate
   - Windows:
     $ python -m venv venv
     $ venv\Scripts\activate

3. Instalar as dependências:
   $ make install

4. Executar a aplicação:
   $ make run

NOTAS DE SEGURANÇA:
- O sistema gera automaticamente um par de chaves RSA na primeira execução.
- As chaves de derivação temporais são geradas determinísticamente com base num segredo interno.
- Recomenda-se a utilização de variáveis de ambiente para definir segredos em produção.

============================================================