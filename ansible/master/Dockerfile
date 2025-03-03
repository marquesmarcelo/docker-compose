# Usar a imagem base do Ubuntu
FROM ubuntu:22.04

# Forçar o apt a funcionar em modo não interativo
ENV DEBIAN_FRONTEND=noninteractive

# Instalar dependências básicas
RUN apt-get update && \
    apt-get install -y openssh-server ssh software-properties-common sudo net-tools telnet vim

# Adicionar o repositório do Ansible
RUN apt-add-repository --yes --update ppa:ansible/ansible

# Instalar o Ansible e o pip
RUN apt-get update && \
    apt-get install -y ansible python3-pip

# Instalar a passlib que permite cifrar senhas no ansible 
RUN pip3 install passlib

# Definir senha para o usuário root
RUN echo 'root:rnpesr' | chpasswd

# Configurar o SSH
# O ideial seria no para os dois parametros abaixo porém por ser um laboratório estou coloando como yes para facilitar testes
RUN mkdir /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Criar diretório .ssh e copiar a chave pública
RUN mkdir -p /root/.ssh && \
    chmod -R 700 /root/.ssh && \
    chown -R root:root /root/.ssh

# Copiar a chave pública e privada do host para o container
COPY ./.ssh/ /root/.ssh/
RUN chmod 600 /root/.ssh/ && \
    chown root:root /root/.ssh/

WORKDIR /ansible

# Expor a porta SSH
EXPOSE 22

# limpar o repositorio apt
RUN  rm -rf /var/lib/apt/lists/*

CMD ["/usr/sbin/sshd", "-D"]