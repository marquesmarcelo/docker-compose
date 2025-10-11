ARG TAG=24.04
# Primeiro estágio, contém apenas a compilação do ambiente padrão
FROM ubuntu:$TAG AS builder

LABEL maintainer="Francisco Marcelo, <marques.marcelo@gmail.com>"
LABEL version="v0.1"

# Evita prompts interativos durante a instalação
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Sao_Paulo

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

RUN git clone https://github.com/neutrinolabs/pulseaudio-module-xrdp.git /pulseaudio-module-xrdp
WORKDIR /pulseaudio-module-xrdp
RUN scripts/install_pulseaudio_sources_apt.sh && \
    ./bootstrap && \
    ./configure PULSE_DIR=$HOME/pulseaudio.src && \
    make && \
    make install DESTDIR=/tmp/install

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


# Limpar o apt
RUN apt clean all
RUN rm -rf /var/lib/apt/lists/*

# -------------------------
# Segundo estágio, build final
FROM ubuntu:$TAG

# Evita prompts interativos durante a instalação
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Sao_Paulo

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
        xorgxrdp \
        xrdp \
        xubuntu-icon-theme && \
    add-apt-repository -y ppa:mozillateam/ppa && \
    echo "Package: *"  > /etc/apt/preferences.d/mozilla-firefox && \
    echo "Pin: release o=LP-PPA-mozillateam" >> /etc/apt/preferences.d/mozilla-firefox && \
    echo "Pin-Priority: 1001" >> /etc/apt/preferences.d/mozilla-firefox && \
    apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends firefox && \
    rm -rf /var/lib/apt/lists/* && \
    deluser --remove-home ubuntu

COPY --from=builder /tmp/install /

RUN sed -i 's|^Exec=.*|Exec=/usr/bin/pulseaudio|' /etc/xdg/autostart/pulseaudio-xrdp.desktop

COPY entrypoint.sh /usr/bin/entrypoint

RUN chmod +x /usr/bin/entrypoint

EXPOSE 22/tcp 3389/tcp

# Limpar o apt
RUN apt clean all
RUN rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/bin/entrypoint"]
