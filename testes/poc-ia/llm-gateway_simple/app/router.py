from app.mcp_client import call_tool


async def route(messages):
    prompt = messages[-1]["content"].lower()

    if "servidor" in prompt:
        return await call_tool(
            "verificar_status_servidor",
            {"id_servidor": "srv-01"}
        )

    return None