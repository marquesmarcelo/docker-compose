# IMPORTANTE

Registrar no arquivo hosts da máquina local o IP da máquina docker que esta executando a aplicação. No exemplo abaixo o IP seria '172.28.217.99'

```bash
172.28.217.99   wazuh.esr.local
```
# Login

* endereço: https://wazuh.esr.local
* usuário: admin
* Senha: SecretPassword

# Deploy Wazuh Docker in single node configuration

This deployment is defined in the `docker-compose.yml` file with one Wazuh manager containers, one Wazuh indexer containers, and one Wazuh dashboard container. It can be deployed by following these steps: 

1) Increase max_map_count on your host (Linux). This command must be run with root permissions:
```bash
$ sysctl -w vm.max_map_count=262144
```
2) Run the certificate creation script:
```bash
$ docker-compose -f generate-indexer-certs.yml run --rm generator
```

# Install wazuh agent

Install the GPG key:

```bash
apt update
apt install -y vim curl gpg wget iputils-ping ssh
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
```

Add the repository:

```bash
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
```

Update the package information:
```bash
apt-get update
```

Deploy a Wazuh agent
```bash
WAZUH_MANAGER='wazuh.manager' WAZUH_AGENT_GROUP='Linux' apt-get install -y wazuh-agent=4.11.1-1
```

Start a Wazu agent

```bash
/etc/init.d/wazuh-agent restart
/etc/init.d/wazuh-agent status
```