# IMPORTANTE

Registrar no arquivo hosts da máquina local o IP da máquina docker que esta executando a aplicação. No exemplo abaixo o IP seria '172.28.217.99'

```bash
172.28.217.99   graylog.esr.local
```
# Login

Após executar o `docker compose up -` para pegar a primeira senha será necessário visualizar os logs do `graylog-server`

```bash
marques@DESKTOP-RB69N9A:/opt/docker-compose/graylog2/enterprise$ docker ps
CONTAINER ID   IMAGE                            COMMAND                  CREATED          STATUS                      PORTS                                                                                                                                                                                                                                                                                                                                                                                                                                   NAMES
d49f910a8d37   graylog/graylog-enterprise:6.1   "/usr/bin/tini -- /d…"   24 minutes ago   Up 24 minutes (unhealthy)   0.0.0.0:5044->5044/tcp, :::5044->5044/tcp, 0.0.0.0:5140->5140/tcp, 0.0.0.0:5140->5140/udp, :::5140->5140/tcp, :::5140->5140/udp, 0.0.0.0:5555->5555/tcp, :::5555->5555/tcp, 0.0.0.0:9000->9000/tcp, 0.0.0.0:5555->5555/udp, :::9000->9000/tcp, :::5555->5555/udp, 0.0.0.0:12201->12201/tcp, :::12201->12201/tcp, 0.0.0.0:13301-13302->13301-13302/tcp, :::13301-13302->13301-13302/tcp, 0.0.0.0:12201->12201/udp, :::12201->12201/udp   enterprise-graylog-1
9b395c815954   graylog/graylog-datanode:6.1     "tini -- /entrypoint…"   24 minutes ago   Up 24 minutes               0.0.0.0:8999->8999/tcp, :::8999->8999/tcp, 0.0.0.0:9200->9200/tcp, :::9200->9200/tcp, 0.0.0.0:9300->9300/tcp, :::9300->9300/tcp                                                                                                                                                                                                                                                                                                         enterprise-datanode-1
8c2c2e15d00a   mongo:6.0                        "docker-entrypoint.s…"   24 minutes ago   Up 24 minutes               27017/tcp                                                                                                                                                                                                                                                                                                                                                                                                                               enterprise-mongodb-1
marques@DESKTOP-RB69N9A:/opt/docker-compose/graylog2/enterprise$ docker logs enterprise-graylog-1

(...)
It seems you are starting Graylog for the first time. To set up a fresh install, a setup interface has
been started. You must log in to it to perform the initial configuration and continue.

Initial configuration is accessible at 0.0.0.0:9000, with username 'admin' and password 'JQuLoiENlD'.
Try clicking on http://admin:JQuLoiENlD@0.0.0.0:9000

========================================================================================================

```

Faça o login com a senha informada abaixo e aproveite para finalizar a configuração gerando o sertificado digital

* endereço: http://localhost:9000
* usuário: admin
* Senha: JQuLoiENlD

Após realizar a configuração a senha , a senha passará a ser `rnpesr`:

* endereço: http://localhost:9000
* usuário: admin
* Senha: JQuLoiENlD


# Deploy Wazuh Docker in single node configuration

This deployment is defined in the `docker-compose.yml` file with one Wazuh manager containers, one Wazuh indexer containers, and one Wazuh dashboard container. It can be deployed by following these steps: 

1) Increase max_map_count on your host (Linux). This command must be run with root permissions:
```bash
$ sysctl -w vm.max_map_count=262144
```