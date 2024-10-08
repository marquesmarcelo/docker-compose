# OBJETIVO

Repositório criado para consolidar arquivos docker-compose para testar ferramentas gratuitas

As instruções para cada ferramenta estão em suas respectivas pastas

## Comandos para gerenciar o container

Iniciar os Serviços:

```bash
docker-compose up -d
```

Parar os Serviços:

```bash
docker-compose down
```

Verificar Logs:

```bash
docker-compose logs -f
```

Para acessar a console de determinado contêiner

```bash
docker exec -it nome_container /bin/bash
```
Limpar o docker

```bash
docker stop $(docker ps -q)
docker system prune -a --volumes
docker volume rm $(docker volume ls -q --filter dangling=true)
```

Compilar container usado por um docker compose

```bash
docker compose up --build
```

Sites e Dicas interessantes:

HTTPS
https://richardatkin.com/post/2022/01/15/Identifying-and-retrieving-certificates-from-a-PCAP-file-using-Wireshark.html