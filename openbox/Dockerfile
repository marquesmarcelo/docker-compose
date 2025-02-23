# Usar uma imagem base leve (Ubuntu minimal)
FROM ubuntu:24.04

# Instalar dependências básicas
RUN apt-get update && apt-get install -y \
    openbox \
    tigervnc-standalone-server \
    tigervnc-tools \
    xterm \
    feh \
    sudo \
    nano \
    vim \
    --no-install-recommends

# Instalar dependências da VM
RUN apt-get update && apt-get install -y \
    wireshark \
    tshark \
    --no-install-recommends

# Apagar o repositório APT
RUN apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Definir a senha do root
RUN echo "root:rnpesr" | chpasswd

# Configurar o diretorio padrao
RUN mkdir -p /etc/skel/.config/openbox
COPY menu.xml /etc/skel/.config/openbox/menu.xml
COPY autostart /etc/skel/.config/openbox/autostart

# Criar usuário 'aluno'
RUN useradd -m -s /bin/bash aluno && \
    echo "aluno:rnpesr" | chpasswd

# Adicionar o usuário 'aluno' ao grupo 'sudo'
RUN usermod -aG sudo aluno

# Configurar o X11VNC para o usuário 'aluno'
USER aluno
RUN mkdir -p /home/aluno/.vnc && \
    echo "rnpesr" | tigervncpasswd -f > /home/aluno/.vnc/passwd && \
    chmod 600 /home/aluno/.vnc/passwd

# Iniciar o servidor VNC para gerar o arquivo .Xauthority
RUN vncserver :1 -geometry 800x600 -depth 16 -localhost no && \
    vncserver -kill :1  # Encerra o servidor após gerar o arquivo

# Voltar execucao para o root
USER root

# Definir a variável DISPLAY para todos os usuários
RUN echo 'export DISPLAY=:1' >> /etc/profile

# Copiar o papel de parede
COPY wallpaper.jpg /usr/share/wallpaper.jpg

# Copiar a configuração do VNC do aluno para o root
RUN mkdir -p /root/.vnc && \
    cp /home/aluno/.Xauthority /root/.Xauthority && \
    cp /home/aluno/.vnc/passwd /root/.vnc/passwd

# Copiar a configuração do VNC aluno para qualquer novo usuário
RUN mkdir -p /etc/skel/.vnc && \
    cp /home/aluno/.Xauthority /etc/skel/.Xauthority && \
    cp /home/aluno/.vnc/passwd /etc/skel/.vnc/passwd

# Expor a porta do VNC
EXPOSE 5901

# Definir o ENTRYPOINT para manter o container em execução
ENTRYPOINT ["su", "-", "aluno", "-c", "vncserver :1 -geometry 1024x768 -depth 16 -localhost no && tail -f /dev/null"]