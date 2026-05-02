import asyncio
import json
import uuid
import httpx
import os

MCP_URL = os.getenv("MCP_URL", "http://mcp-hub:8000")


class MCPClient:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=60)
        self.session_id = None
        self.queue = asyncio.Queue()
        self.listener_task = None

    async def connect(self):
        if self.listener_task:
            return

        print("Conectando no MCP...")

        async def listen():
            async with self.client.stream("GET", f"{MCP_URL}/sse") as resp:
                async for line in resp.aiter_lines():
                    if not line:
                        continue

                    print("MCP SSE:", line)

                    if line.startswith("data:"):
                        payload = line.replace("data:", "").strip()

                        if payload.startswith("/messages?session_id="):
                            self.session_id = payload.split("session_id=")[1]
                            print("MCP session:", self.session_id)
                            continue

                        try:
                            msg = json.loads(payload)
                            await self.queue.put(msg)
                        except Exception:
                            pass

        self.listener_task = asyncio.create_task(listen())

        while not self.session_id:
            await asyncio.sleep(0.1)

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

        print("POST MCP:", payload)

        await self.client.post(
            f"{MCP_URL}/messages?session_id={self.session_id}",
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