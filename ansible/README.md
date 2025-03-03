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

Antes de iniciar vamos coletar as chaves públicas das VMs e adicioná-las ao arquivo known_hosts da máquina control-node usando o commando ssh-keyscan

Execute o playbook:

```bash
ansible-playbook -i hosts ./playbook/add_known_hosts.yml
```

Isso adicionará automaticamente as chaves públicas de todas as VMs ao arquivo known_hosts.

# Testando a configuração

Testar a conexão com todas as VMs

Obs.: irá falhar a VM3 pois ela não foi criada

```bash
ansible -i hosts all -m ping
```

Instalar o nginx nas VMs do grupo Web

```bash
ansible-playbook -i hosts web_hosts_playbook.yml
```