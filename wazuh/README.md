# IMPORTANTE

Registrar no arquivo hosts da máquina local o IP da máquina docker que esta executando a aplicação. No exemplo abaixo o IP seria '172.28.217.99'

```conf
172.28.217.99   wazuh.esr.local
```
# Login

* endereço: https://wazuh.esr.local
* usuário: admin
* Senha: SecretPassword

# Deploy Wazuh Docker in single node configuration

This deployment is defined in the `docker-compose.yml` file with one Wazuh manager containers, one Wazuh indexer containers, and one Wazuh dashboard container. It can be deployed by following these steps: 

1) Increase max_map_count on your host (Linux). This command must be run with root permissions:
```
$ sysctl -w vm.max_map_count=262144
```
2) Run the certificate creation script:
```
$ docker-compose -f generate-indexer-certs.yml run --rm generator
```