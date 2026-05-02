import json
import re
import uuid
import httpx

MCP_URL = "http://mcp-hub:8000"


async def call_tool(tool_name: str, arguments: dict):
    async with httpx.AsyncClient(timeout=60) as client:
        async with client.stream("GET", f"{MCP_URL}/sse") as sse:

            session_id = None
            initialized = False

            async for line in sse.aiter_lines():

                if not line.startswith("data:"):
                    continue

                data = line.replace("data:", "").strip()

                if not data:
                    continue

                print("SSE:", data)

                #
                # 1) captura session_id
                #
                if session_id is None:
                    m = re.search(r"session_id=([^&]+)", data)

                    if m:
                        session_id = m.group(1)

                        init_payload = {
                            "jsonrpc": "2.0",
                            "id": str(uuid.uuid4()),
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {
                                    "name": "llm-gateway",
                                    "version": "1.0"
                                }
                            }
                        }

                        await client.post(
                            f"{MCP_URL}/messages?session_id={session_id}",
                            json=init_payload,
                            headers={
                                "Content-Type": "application/json"
                            },
                        )

                    continue

                #
                # 2) espera initialize responder
                #
                try:
                    msg = json.loads(data)

                    if not initialized:
                        if "result" in msg:
                            initialized = True

                            tool_payload = {
                                "jsonrpc": "2.0",
                                "id": str(uuid.uuid4()),
                                "method": "tools/call",
                                "params": {
                                    "name": tool_name,
                                    "arguments": arguments
                                }
                            }

                            await client.post(
                                f"{MCP_URL}/messages?session_id={session_id}",
                                json=tool_payload,
                                headers={
                                    "Content-Type": "application/json"
                                },
                            )

                        continue

                    #
                    # 3) resultado da tool
                    #
                    if "result" in msg:
                        content = msg["result"]["content"][0]["text"]
                        return content

                except Exception:
                    pass

    return None