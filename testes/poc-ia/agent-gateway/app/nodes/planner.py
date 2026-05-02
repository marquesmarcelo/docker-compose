import re


def extract_server(text: str):
    """
    Extrai srv-01 / srv-02 / srv-abc... (retorna o último mencionado)
    """
    matches = re.findall(r"\b(srv[-\w]+)\b", text.lower())
    if matches:
        return matches[-1]
    return None


async def planner_node(state: dict):
    """
    Decide para onde roteia:
    - MCP
    - n8n
    - LLM
    """

    question = state["question"].lower()

    print(f"[PLANNER] question={question}")

    # -------------------------
    # rota MCP
    # -------------------------
    server_id = extract_server(question)

    if server_id and any(
        word in question
        for word in [
            "status",
            "servidor",
            "online",
            "offline",
            "cpu",
            "memoria",
            "memória",
            "disco",
        ]
    ):
        route = {
            **state,
            "route": "mcp",
            "tool": "verificar_status_servidor",
            "tool_args": {
                "id_servidor": server_id
            },
        }

        print("[PLANNER] -> MCP")
        return route

    # -------------------------
    # rota n8n
    # -------------------------
    if any(
        word in question
        for word in [
            "abrir chamado",
            "aprovar",
            "solicitar acesso",
            "workflow",
            "ticket",
        ]
    ):
        print("[PLANNER] -> N8N")

        return {
            **state,
            "route": "n8n",
        }

    # -------------------------
    # fallback LLM
    # -------------------------
    print("[PLANNER] -> LLM")

    return {
        **state,
        "route": "llm",
    }