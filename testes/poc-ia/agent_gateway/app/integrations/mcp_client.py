import asyncio
import json
import uuid
import httpx

from app.config import settings, get_logger

logger = get_logger(__name__)

class MCPClient:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=60)
        self.session_id = None
        self.queue = asyncio.Queue()
        self.listener_task = None

    async def connect(self):
        if self.listener_task:
            return

        logger.info("Conectando no MCP...")

        async def listen():
            while True:
                try:
                    async with self.client.stream("GET", f"{settings.MCP_URL}/sse") as resp:
                        resp.raise_for_status()
                        async for line in resp.aiter_lines():
                            if not line:
                                continue

                            logger.debug(f"MCP SSE: {line}")

                            if line.startswith("data:"):
                                payload = line.replace("data:", "").strip()

                                if payload.startswith("/messages?session_id="):
                                    self.session_id = payload.split("session_id=")[1]
                                    logger.info(f"MCP session: {self.session_id}")
                                    continue

                                try:
                                    msg = json.loads(payload)
                                    await self.queue.put(msg)
                                except Exception:
                                    pass
                except httpx.ReadError as e:
                    logger.warning(f"Conexão com MCP interrompida (ReadError): {e}. Tentando reconectar...")
                except Exception as e:
                    logger.error(f"Erro no Listener do MCP: {e}. Tentando reconectar em 5s...", exc_info=True)
                
                # Se falhar, reseta a session para forçar novo setup e espera um pouco
                self.session_id = None
                await asyncio.sleep(5)

        self.listener_task = asyncio.create_task(listen())

        while not self.session_id:
            await asyncio.sleep(0.1)

        # -----------------------------
        # Realizar inicialização do MCP
        # -----------------------------
        init_id = str(uuid.uuid4())
        init_payload = {
            "jsonrpc": "2.0",
            "id": init_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "agent-gateway",
                    "version": "1.0.0"
                }
            }
        }
        await self.client.post(
            f"{settings.MCP_URL}/messages?session_id={self.session_id}",
            json=init_payload,
        )

        # Aguardar resposta do initialize
        while True:
            msg = await self.queue.get()
            if msg.get("id") == init_id:
                if "error" in msg:
                    raise Exception(f"Erro no initialize: {msg['error']}")
                break

        # Enviar notification de initialized
        notif_payload = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }
        await self.client.post(
            f"{settings.MCP_URL}/messages?session_id={self.session_id}",
            json=notif_payload,
        )

    async def call_tool(self, tool_name: str, arguments: dict):
        await self.connect()

        request_id = str(uuid.uuid4())

        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }

        logger.info(f"POST MCP Tool Call: {tool_name}")
        logger.debug(f"Payload: {payload}")

        await self.client.post(
            f"{settings.MCP_URL}/messages?session_id={self.session_id}",
            json=payload,
        )

        while True:
            msg = await self.queue.get()

            if msg.get("id") != request_id:
                continue

            if "error" in msg:
                raise Exception(msg["error"])

            return msg["result"]


mcp = MCPClient()