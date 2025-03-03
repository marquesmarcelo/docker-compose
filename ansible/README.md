# Geração da chave (já executado na máquina mãe para ser copiado para os containers)
```bash
ssh-keygen -t rsa -b 4096 -C "ansible@master"
cp /root/.ssh/* ./master/.ssh/
cp /root/.ssh/id_rsa.pub ./slave/.ssh/id_rsa.pub
```

# Inciando a simulação
```bash
docker compose up -d
```

# Acessando o conteiner controle

```bash
docker exec -it master bash
```
## Autenticação

Usuário: root ou aluno
Senha: rnpesr

# Comandos para finalizar a configuração do ansible

Antes de iniciar vamos coletar as chaves públicas das VMs e adicioná-las ao arquivo known_hosts da máquina master usando o commando ssh-keyscan

Execute o playbook:

```bash
ansible-playbook -i hosts ./playbook/add_known_hosts.yml
```

# Testando a configuração

Testar a conexão com todas as VMs

Obs.: irá falhar a VM3 pois ela não foi criada

```bash
ansible -i hosts all -m ping
```

Aplicar algumas configurações interessantes no container

```bash
ansible-playbook -i hosts ./playbook/ntp.yml
ansible-playbook -i hosts ./playbook/syslog-ng.yml
ansible-playbook -i hosts ./playbook/zabbix-agent.yml
ansible-playbook -i hosts ./playbook/change_root_password.yml
```

Instalar o nginx apenas nas VMs do grupo Web

```bash
ansible-playbook -i hosts ./playbook/web_hosts.yml
```

Rotacionar a chave privada em todos os nós

```bash
ansible-playbook -i hosts ./playbook/rotate_private_key.yml
```