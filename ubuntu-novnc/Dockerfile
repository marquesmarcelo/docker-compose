FROM ubuntu:24.04

LABEL maintainer="Francisco Marcelo, <marques.marcelo@gmail.com>"
LABEL version="v0.1"

# Evita prompts interativos durante a instalação
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Sao_Paulo

# Evita prompts interativos durante a instalação
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=America/Sao_Paulo \
    VNC_PASSWORD="changeme" \
    VNC_RESOLUTION="1024x768" \
    VNC_PORT="5900" \
    NOVNC_PORT="6080"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        autoconf \
        build-essential \
        ca-certificates \
        dpkg-dev \
        libpulse-dev \
        lsb-release \
        git \
        libtool \
        libltdl-dev \
        sudo \
        inetutils-ping net-tools iproute2 ufw tcpdump \
        curl wget sudo vim nano \
        openssh-server ssh openssh-client \
        apt-transport-https ca-certificates software-properties-common

# Cria usuário 'aluno' com senha 'rnpesr' e acesso sudo
RUN useradd -m -s /bin/bash aluno && \
    echo "aluno:rnpesr" | chpasswd

# Trocar a senha do root para conteúdo complexo e restrito
RUN echo "root:rnpesr" | chpasswd

# Remover o usuário default
RUN deluser --remove-home ubuntu

# Permite login com senha (opcional, mas útil para testes)
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Instalar suporte a portugues na VM
#RUN apt install -y language-pack-pt language-pack-pt-base
#RUN update-locale LANG=pt_BR.UTF-8

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        dbus-x11 \
        git \
        locales \
        pavucontrol \
        pulseaudio \
        pulseaudio-utils \
        software-properties-common \
        sudo \
        vim \
        x11-xserver-utils \
        xfce4 \
        xfce4-goodies \
        xfce4-pulseaudio-plugin \
        xubuntu-icon-theme

RUN add-apt-repository -y ppa:mozillateam/ppa && \
    echo "Package: *"  > /etc/apt/preferences.d/mozilla-firefox && \
    echo "Pin: release o=LP-PPA-mozillateam" >> /etc/apt/preferences.d/mozilla-firefox && \
    echo "Pin-Priority: 1001" >> /etc/apt/preferences.d/mozilla-firefox && \
    apt-get update && \
    apt-get install -y --no-install-recommends firefox

RUN apt-get update && apt-get install -y --no-install-recommends \
    xfce4 \
    x11vnc \
    novnc \
    xvfb \
    wget \
    git \
    python3 \
    python3-pip \
    dbus-x11 \
    net-tools \
    remmina

# Copia script de inicialização
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

RUN apt-get install -y --no-install-recommends gnupg2 gnupg-agent

# Troca o texto do logo nos arquivos HTML usando sed
RUN sed -i 's|<span>no</span><br>VNC|<span>ESR/</span><br>RNP|g' /usr/share/novnc/vnc.html && \
    sed -i 's|<span>no</span>VNC|<span>ESR/</span>RNP|g' /usr/share/novnc/vnc.html


# Limpar o apt
RUN apt clean all
RUN rm -rf /var/lib/apt/lists/*

# Alterna para o usuário 'aluno'
USER aluno

# Define o diretório de trabalho do usuário
WORKDIR /home/aluno

# Cria o diretório .vnc para o usuário 'aluno'
RUN mkdir -p /home/aluno/.vnc
RUN mkdir -p /tmp/.X11-unix
RUN touch /home/aluno/.Xauthority



EXPOSE ${NOVNC_PORT}
EXPOSE ${VNC_PORT}


ENTRYPOINT ["/usr/local/bin/start.sh"]
