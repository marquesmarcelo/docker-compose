# Build xrdp pulseaudio modules in builder container
# See https://github.com/neutrinolabs/pulseaudio-module-xrdp/wiki/README
FROM kalilinux/kali-rolling
LABEL maintainer="Francisco Marcelo, <marques.marcelo@gmail.com>"
LABEL version="v0.1"

# Evita prompts interativos durante a instalação
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Sao_Paulo

RUN apt-get update
RUN apt-get install -y --no-install-recommends \
        autoconf \
        build-essential \
        ca-certificates \
        dpkg-dev \
        libpulse-dev \
        lsb-release \
        git \
        libtool \
        libltdl-dev \
        doxygen \
        sudo \
        openssh-server ssh openssh-client

RUN git clone https://github.com/neutrinolabs/pulseaudio-module-xrdp.git /pulseaudio-module-xrdp
WORKDIR /pulseaudio-module-xrdp
RUN scripts/install_pulseaudio_sources_apt.sh && \
    ./bootstrap && \
    ./configure PULSE_DIR=$HOME/pulseaudio.src && \
    make && \
    make install DESTDIR=/tmp/install

RUN apt-get install -y --no-install-recommends \
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
        firefox-esr \          
        xrdp

# Cria usuário 'aluno' com senha 'rnpesr' e acesso sudo
RUN useradd -m -s /bin/bash aluno && \
    echo "aluno:rnpesr" | chpasswd

# Trocar a senha do root para conteúdo complexo e restrito
RUN echo "root:rnpesr" | chpasswd

# Permite login com senha (opcional, mas útil para testes)
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

RUN apt install -y --no-install-recommends \
   kali-themes-purple \
   kali-tools-detect \
   kali-tools-identify \
   kali-tools-protect \
   kali-tools-respond \
   kali-tools-recover

#RUN sed -i 's|^Exec=.*|Exec=/usr/bin/pulseaudio|' /etc/xdg/autostart/pulseaudio-xrdp.desktop

RUN apt install -y --no-install-recommends \
    xfce4-power-manager xfce4-power-manager-plugins xfce4-goodies

# Limpar o apt
RUN apt clean all
RUN rm -rf /var/lib/apt/lists/*

EXPOSE 3389/tcp
EXPOSE 22/tcp

COPY entrypoint.sh /usr/bin/entrypoint
RUN chmod +x /usr/bin/entrypoint
ENTRYPOINT ["/usr/bin/entrypoint"]
