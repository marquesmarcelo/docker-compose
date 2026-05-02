import re
from app.config import get_logger

logger = get_logger(__name__)

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
    - RAG
    - LLM
    """

    question = state["question"].lower()

    logger.info(f"[PLANNER] question={question}")

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

        logger.info("[PLANNER] -> MCP")
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
        logger.info("[PLANNER] -> N8N")

        return {
            **state,
            "route": "n8n",
        }

    # -------------------------
    # rota RAG
    # -------------------------
    if any(
        word in question
        for word in [
            "norma",
            "documento",
            "manual",
            "procedimento",
        ]
    ):
        logger.info("[PLANNER] -> RAG")

        return {
            **state,
            "route": "rag",
        }

    # -------------------------
    # fallback LLM
    # -------------------------
    logger.info("[PLANNER] -> LLM")

    return {
        **state,
        "route": "llm",
    }