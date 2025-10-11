#!/bin/bash
set -e

export DISPLAY=:1

echo "==> Iniciando servidor X virtual (Xvfb)..."
Xvfb $DISPLAY -screen 0 ${VNC_RESOLUTION}x16 -auth /home/aluno/.Xauthority &
sleep 2

echo "==> Iniciando XFCE..."
startxfce4 &
sleep 5

echo "==> Configurando senha do VNC..."
mkdir -p /home/aluno/.vnc
x11vnc -storepasswd "$VNC_PASSWORD" /home/aluno/.vnc/passwd

echo "==> Iniciando servidor VNC..."
x11vnc -display $DISPLAY -rfbauth /home/aluno/.vnc/passwd -forever -shared -rfbport $VNC_PORT -auth /home/aluno/.Xauthority &
sleep 2

echo "==> Iniciando noVNC (websockify)..."
websockify --web /usr/share/novnc 0.0.0.0:$NOVNC_PORT localhost:$VNC_PORT &

echo "==> noVNC rodando em: http://localhost:${NOVNC_PORT}/vnc.html"
echo "==> Login VNC: senha definida em \$VNC_PASSWORD"

# Mantém o container rodando
tail -f /dev/null
