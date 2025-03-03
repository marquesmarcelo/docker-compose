# Usar a imagem base do Ubuntu
FROM ubuntu:22.04

# Forçar o apt a funcionar em modo não interativo
ENV DEBIAN_FRONTEND=noninteractive

# Instalar dependências básicas
RUN apt-get update && \
    apt-get install -y openssh-server ssh software-properties-common sudo net-tools telnet vim

# Criar o usuário ansible
RUN useradd -m -s /bin/bash ansible && \
    echo "ansible ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ansible && \
    chmod 0440 /etc/sudoers.d/ansible

# Definir senha para o usuário root
RUN echo 'root:rnpesr' | chpasswd

# Definir senha para o usuário ansible
RUN echo 'ansible:rnpesr' | chpasswd

# Configurar o SSH
# O ideial seria no para os dois parametros abaixo porém por ser um laboratório estou coloando como yes para facilitar testes
RUN mkdir /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Criar diretório .ssh e copiar a chave pública
RUN mkdir -p /home/ansible/.ssh && \
    chmod -R 700 /home/ansible/.ssh && \
    chown -R ansible:ansible /home/ansible/.ssh

# Copiar a chave pública do host para o container
COPY ./.ssh/id_rsa.pub /home/ansible/.ssh/authorized_keys
RUN chmod 600 /home/ansible/.ssh/authorized_keys && \
    chown ansible:ansible /home/ansible/.ssh/authorized_keys

# Expor a porta SSH
EXPOSE 22 80

# limpar o repositorio apt
RUN  rm -rf /var/lib/apt/lists/*

CMD ["/usr/sbin/sshd", "-D"]