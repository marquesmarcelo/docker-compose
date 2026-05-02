import os
import httpx
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from mcp.server import Server
from mcp.types import Tool, TextContent
from mcp.server.streamable_http import StreamableHTTPServerTransport

# =========================
# LOGS
# =========================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-infra-dpu")

API_URL = os.getenv("API_URL", "http://fake-api:8000")

# =========================
# MCP SERVER
# =========================
mcp_server = Server("Gerenciador-Infra-Soberana")


# =========================
# TOOLS
# =========================
@mcp_server.list_tools()
async def handle_list_tools() -> list[Tool]:
    return [
        Tool(
            name="verificar_status_servidor",
            description="Consulta status de servidor pelo ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "id_servidor": {"type": "string"}
                },
                "required": ["id_servidor"]
            },
        ),
        Tool(
            name="listar_inventario_completo",
            description="Lista inventário completo.",
            inputSchema={"type": "object", "properties": {}},
        )
    ]


# =========================
# EXECUTION
# =========================
@mcp_server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:

            if name == "verificar_status_servidor":
                id_srv = arguments["id_servidor"]

                r = await client.get(f"{API_URL}/items/{id_srv}")

                if r.status_code == 200:
                    d = r.json()
                    text = f"{d['nome']} está {d['status']} (CPU {d['cpu']})"
                else:
                    text = "Servidor não encontrado"

                return [TextContent(type="text", text=text)]

            if name == "listar_inventario_completo":
                r = await client.get(f"{API_URL}/items")
                data = r.json()

                text = "\n".join(
                    f"- {k}: {v['nome']} ({v['status']})"
                    for k, v in data.items()
                )

                return [TextContent(type="text", text=text)]

        except Exception as e:
            return [TextContent(type="text", text=str(e))]


# =========================
# FASTAPI
# =========================
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("MCP iniciado")
    yield
    logger.info("MCP finalizado")


app = FastAPI(lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])


# =========================
# FIX PRINCIPAL AQUI
# =========================
@app.post("/mcp")
async def mcp_endpoint(request: Request):
    """
    MCP Streamable HTTP endpoint
    """

    session_id = request.headers.get("mcp-session-id", "default-session")

    transport = StreamableHTTPServerTransport(
        mcp_session_id=session_id
    )

    return await transport.handle_request(
        request.scope,
        request.receive,
        request._send
    )


# =========================
# START
# =========================
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)