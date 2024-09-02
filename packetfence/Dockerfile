# Usar uma imagem base do Ubuntu
FROM debian:bullseye 

# Definir o mantenedor do Dockerfile
LABEL maintainer="marques.marcelo@gmail.com"

# Atualizar o repositório
RUN apt-get update

# Instala pacotes basicos
RUN apt install -y gnupg sudo wget

# Baixar a chave do repositorio do packetfence
RUN wget -q -O - https://inverse.ca/downloads/GPG_PUBLIC_KEY | gpg --dearmor > /usr/share/keyrings/inverse-archive-keyring.gpg

# Adicionar o repositório do PacketFence
RUN echo 'deb [signed-by=/usr/share/keyrings/inverse-archive-keyring.gpg] http://inverse.ca/downloads/PacketFence/debian/13.2 bullseye bullseye ' > \
/etc/apt/sources.list.d/packetfence.list

# Instalar o PacketFence
RUN apt-get update && apt-get install -y packetfence

# apagar pacotes baixados
RUN apt-get clean

# Expor as portas necessárias
EXPOSE 80 443 1812 1813 1194 3306

# Comando para iniciar o PacketFence
CMD ["/usr/local/pf/bin/pfcmd", "start", "--no-daemonize"]
