import uuid
import json
import asyncio
import httpx

MCP_URL = "http://mcp-hub:8000"

session_id = None
client = None
sse_response = None
connect_lock = asyncio.Lock()


async def connect():
    """
    Abre conexão SSE persistente com MCP Hub
    e captura session_id.
    """
    global session_id, client, sse_response

    print("Conectando ao MCP Hub...")

    if client:
        await client.aclose()

    client = httpx.AsyncClient(timeout=None)

    req = client.build_request(
        "GET",
        f"{MCP_URL}/sse"
    )

    sse_response = await client.send(
        req,
        stream=True
    )

    async for line in sse_response.aiter_lines():
        print("SSE:", line)

        if not line.startswith("data:"):
            continue

        endpoint = line.replace("data:", "").strip()

        if "session_id=" in endpoint:
            session_id = endpoint.split("session_id=")[1]
            print(f"MCP conectado. session_id={session_id}")
            return

    raise Exception("Não recebeu session_id do MCP")


async def ensure_connected():
    """
    Garante conexão ativa.
    """
    global session_id, sse_response

    if session_id and sse_response:
        return

    async with connect_lock:
        if session_id and sse_response:
            return

        await connect()


async def call_tool(tool_name: str, arguments: dict):
    """
    Chama uma tool MCP via JSON-RPC.
    """
    global client, sse_response

    await ensure_connected()

    request_id = str(uuid.uuid4())

    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    }

    print("POST MCP:", payload)

    response = await client.post(
        f"{MCP_URL}/messages?session_id={session_id}",
        json=payload
    )

    response.raise_for_status()

    async for line in sse_response.aiter_lines():
        if not line:
            continue

        print("SSE:", line)

        if not line.startswith("data:"):
            continue

        raw = line.replace("data:", "").strip()

        if not raw:
            continue

        try:
            msg = json.loads(raw)
        except Exception:
            continue

        print("MCP RAW:", msg)

        # ignora mensagens de outros requests
        if msg.get("id") != request_id:
            continue

        # erro MCP
        if "error" in msg:
            raise Exception(f"MCP Error: {msg['error']}")

        # sucesso
        if "result" in msg:
            result = msg["result"]

            content = result.get("content", [])

            if content and isinstance(content, list):
                first = content[0]

                if isinstance(first, dict):
                    if "text" in first:
                        return first["text"]

            return str(result)

    raise Exception("Resposta MCP não recebida")