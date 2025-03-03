# Usar a imagem base do Ubuntu
FROM ubuntu:22.04

# Instalar dependências básicas
RUN apt-get update && \
    apt-get install -y openssh-server sudo net-tools telnet && \
    apt-get install -y ssh sudo software-properties-common

# Adicionar o repositório do Ansible
RUN apt-add-repository --yes --update ppa:ansible/ansible

# Instalar o Ansible
RUN apt-get update && \
    apt-get install -y ansible && \
    rm -rf /var/lib/apt/lists/*

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

# Configurar HashKnownHosts para eviar armazenar um hash no 
RUN sed -i '/^#?HashKnownHosts/s/^.*$/HashKnownHosts no/' /etc/ssh/ssh_config || echo "HashKnownHosts no" >> /etc/ssh/ssh_config

WORKDIR /ansible

# Expor a porta SSH
EXPOSE 22

# Definir o comando de inicialização
ENTRYPOINT ["/usr/local/bin/startup.sh"]
CMD ["/usr/sbin/sshd", "-D"]