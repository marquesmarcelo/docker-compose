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