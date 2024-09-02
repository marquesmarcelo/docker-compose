# Use uma imagem base do Ubuntu
FROM ubuntu:20.04

# Instale Ansible e SSH
RUN apt-get update && apt-get install -y ansible openssh-server

# Configure SSH
RUN mkdir /var/run/sshd
RUN echo 'root:root' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config
RUN sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
RUN mkdir -p /root/.ssh

# Copie a chave pública do master para os nodes
COPY ssh_config/master.pub /root/.ssh/authorized_keys

# Copie a chave privada do master
COPY ssh_config/master /root/.ssh/id_rsa
RUN chmod 600 /root/.ssh/id_rsa
RUN chmod 600 /root/.ssh/authorized_keys

# Inicie o serviço SSH
CMD ["/usr/sbin/sshd", "-D"]
