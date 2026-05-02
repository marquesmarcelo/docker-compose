# Testando o SSE com o curl

1. Abra dois terminais

2. No terminal 1, rode: 
```bash
$ curl -N http://localhost:8082/sse
```
3. No terminal 2, rode:

```bash
curl -s -X POST "http://localhost:8082/messages?session_id=6d21f0f90eaf4bd0b4c4141514a7786b"      -H "Content-Type: application/json"      -d '{
       "jsonrpc": "2.0",
       "method": "notifications/initialized"
     }'

$ curl -X POST "http://localhost:8082/messages?session_id=6d21f0f90eaf4bd0b4c4141514a7786b"      -H "Content-Type: application/json"      -d '{
       "jsonrpc": "2.0",
       "id": 4,
       "method": "tools/call",
       "params": {
         "name": "verificar_status_servidor",
         "arguments": {
           "id_servidor": "srv-01"
         }
       }
     }'  
```

4. Retorne ao terminar 1 e veja a resposta:
```bash
event: message
data: {"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"Relatório de srv-01: Servidor de Produção está online. CPU: 12% | Mem: 4GB/16GB."}],"isError":false}}
```

# Como testar no Open WebUI:

1. Suba tudo com docker-compose up -d.

2. No Open WebUI, vá em Settings > Connections > MCP Servers.

3. Escolha o tipo SSE.

4. Nome: MeuAppFake.

5. URL: [http://host.docker.internal:8080/sse](http://host.docker.internal:8080/sse) (se o Open WebUI estiver no Docker) ou http://localhost:8080/sse.

6. No chat, você verá um ícone de "ferramenta". Tente perguntar: "Como está o status do cluster srv-02?". O Ollama usará sua ferramenta para responder.