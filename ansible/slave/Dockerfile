# Usar a imagem base do Ubuntu
FROM ubuntu:22.04

# Instalar dependências básicas
RUN apt-get update && \
    apt-get install -y openssh-server sudo net-tools telnet && \
    rm -rf /var/lib/apt/lists/*

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

# Remover as chaves SSH padrão geradas durante a construção da imagem
RUN rm -f /etc/ssh/ssh_host_*

# Criar um script para regenerar as chaves SSH no início do contêiner
RUN echo '#!/bin/bash\n\
rm -f /etc/ssh/ssh_host_*\n\
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""\n\
ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_key -N ""\n\
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""\n\
exec "$@"' > /usr/local/bin/startup.sh

# Tornar o script executável
RUN chmod +x /usr/local/bin/startup.sh

# Expor a porta SSH
EXPOSE 22 80

# Definir o comando de inicialização
ENTRYPOINT ["/usr/local/bin/startup.sh"]
CMD ["/usr/sbin/sshd", "-D"]