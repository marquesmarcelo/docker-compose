import os
import httpx
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from mcp.server import Server
from mcp.types import Tool, TextContent
from mcp.server.sse import SseServerTransport

# 1. Configuração de Logs Corporativos
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-infra-dpu")

# URL da sua Fake API definida no docker-compose
API_URL = os.getenv("API_URL", "http://fake-api:8000")

# 2. Inicialização do Servidor MCP (SDK Oficial Anthropic)
mcp_server = Server("Gerenciador-Infra-Soberana")

# 3. Definição das Ferramentas (Tools) disponíveis para o LLM
@mcp_server.list_tools()
async def handle_list_tools() -> list[Tool]:
    """Lista as capacidades do servidor para o Open WebUI."""
    return [
        Tool(
            name="verificar_status_servidor",
            description="Consulta o status em tempo real de um servidor ou banco de dados pelo ID (ex: srv-01).",
            inputSchema={
                "type": "object",
                "properties": {
                    "id_servidor": {
                        "type": "string", 
                        "description": "O identificador único do recurso."
                    }
                },
                "required": ["id_servidor"],
            },
        ),
        Tool(
            name="listar_inventario_completo",
            description="Retorna uma lista resumida de todos os ativos de TI cadastrados no sistema.",
            inputSchema={"type": "object", "properties": {}},
        )
    ]

# 4. Lógica de Execução (Chamada das Ferramentas)
@mcp_server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Executa a lógica de negócio consumindo a Fake API."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            if name == "verificar_status_servidor":
                id_srv = arguments.get("id_servidor")
                logger.info(f"Consultando status do servidor: {id_srv}")
                print(f"Consultando status do servidor: {id_srv}")
                
                response = await client.get(f"{API_URL}/items/{id_srv}")
                if response.status_code == 200:
                    d = response.json()
                    res = f"Relatório de {id_srv}: {d['nome']} está {d['status']}. CPU: {d['cpu']} | Mem: {d['memoria']}."
                else:
                    res = f"Aviso: O recurso '{id_srv}' não foi encontrado no inventário."
                
                return [TextContent(type="text", text=res)]

            elif name == "listar_inventario_completo":
                logger.info("Listando inventário completo")
                response = await client.get(f"{API_URL}/items")
                itens = response.json()
                resumo = "\n".join([f"- {k}: {v['nome']} ({v['status']})" for k, v in itens.items()])
                return [TextContent(type="text", text=f"Inventário de Ativos:\n{resumo}")]

        except Exception as e:
            logger.error(f"Erro ao processar ferramenta {name}: {str(e)}")
            return [TextContent(type="text", text=f"Falha técnica na integração: {str(e)}")]

# 5. Configuração do Transporte SSE (Server-Sent Events)
# O endpoint /messages é onde o cliente enviará os comandos POST
sse = SseServerTransport("/messages")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gerencia o ciclo de vida da aplicação FastAPI."""
    logger.info("Iniciando MCP Server Gateway...")
    yield
    logger.info("Encerrando MCP Server Gateway...")

app = FastAPI(lifespan=lifespan, title="MCP Infrastructure Gateway")

# Middleware essencial para rodar em containers (resolve o erro 421)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

@app.get("/sse")
async def handle_sse(request: Request):
    """Estabelece a conexão persistente SSE com o Open WebUI."""
    async with sse.connect_sse(
        request.scope, 
        request.receive, 
        request._send
    ) as (read_stream, write_stream):
        # Na versão v1.x, passamos apenas os streams. 
        # O transporte já gerencia os handlers internamente.
        await mcp_server.run(
            read_stream,
            write_stream,
            mcp_server.create_initialization_options()
        )

@app.post("/messages")
async def handle_messages(request: Request):
    """Trata as mensagens individuais enviadas pelo protocolo MCP via POST."""
    # handle_post_message é o novo nome para handle_post_request na v1.x
    return await sse.handle_post_message(request.scope, request.receive, request._send)

if __name__ == "__main__":
    import uvicorn
    # Escutando em 0.0.0.0 para ser acessível externamente ao container
    uvicorn.run(app, host="0.0.0.0", port=8000)