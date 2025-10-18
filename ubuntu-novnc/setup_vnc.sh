#!/bin/bash
#!/bin/bash
set -e

echo "==> Configurando senha do VNC..."
x11vnc -storepasswd $VNC_PASSWORD /home/aluno/.vnc/passwd
chown -R aluno:aluno /home/aluno/.vnc
echo "Senha do VNC armazenada em /home/aluno/.vnc/passwd"