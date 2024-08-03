# Use uma imagem base do Python
FROM python:3.9-slim

# Instale as dependências
RUN pip install flask

# Copie o código do servidor para o contêiner
COPY server.py /server.py

# Defina o diretório de trabalho
WORKDIR /

# Comando para iniciar o servidor web
CMD ["python", "server.py"]
