FROM ubuntu:24.10

LABEL maintainer="Francisco Marcelo, <marques.marcelo@gmail.com>"
LABEL version="v0.1"

# Evita prompts interativos durante a instalação
ENV DEBIAN_FRONTEND=noninteractive

RUN apt update 
RUN apt install -y inetutils-ping net-tools iproute2 ufw tcpdump \
        curl wget sudo vim nano \
		openssh-server openssh-client \
        apt-transport-https ca-certificates software-properties-common

# Cria usuário 'aluno' com senha 'rnpesr' e acesso sudo
RUN useradd -m -s /bin/bash aluno && \
    echo "aluno:rnpesr" | chpasswd && \
    usermod -aG sudo aluno

# Trocar a senha do root
RUN echo "root:rnpesr" | chpasswd

# Permite login com senha (opcional, mas útil para testes)
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Instalar suporte a portugues na VM
RUN apt install -y language-pack-pt language-pack-pt-base
RUN update-locale LANG=pt_BR.UTF-8

# Instalar GUI
RUN apt install -y lxde lightdm

# Limpar imagem
RUN apt clean && rm -rf /var/lib/apt/lists/*

# Expõe a porta padrão do SSH
EXPOSE 22

# Comando para iniciar o SSH
CMD ["/usr/sbin/sshd", "-D"]
