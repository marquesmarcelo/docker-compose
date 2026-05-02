import httpx
from app.config import settings, get_logger

logger = get_logger(__name__)

async def n8n_node(state: dict):
    """
    Dispara workflow no n8n.
    """
    question = state["question"]

    logger.info("[N8N NODE] calling workflow...")

    payload = {
        "question": question,
        "context": state,
    }

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                settings.N8N_WEBHOOK,
                json=payload,
            )

            resp.raise_for_status()

            data = resp.json()

        if isinstance(data, list) and len(data) > 0:
            data = data[0]
            
        if isinstance(data, dict):
            answer = data.get("answer", data.get("message", "Workflow executado com sucesso."))
        else:
            answer = str(data)
            
    except Exception as e:
        logger.error(f"Erro ao disparar fluxo N8N: {e}", exc_info=True)
        answer = "Erro ao executar o workflow."

    return {
        **state,
        "answer": answer,
    }