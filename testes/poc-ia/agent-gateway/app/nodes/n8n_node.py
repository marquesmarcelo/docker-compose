import os
import httpx


N8N_WEBHOOK = os.getenv(
    "N8N_WEBHOOK",
    "http://n8n:5678/webhook/agent"
)


async def n8n_node(state: dict):
    """
    Dispara workflow no n8n.
    """

    question = state["question"]

    print("[N8N NODE] calling workflow...")

    payload = {
        "question": question,
        "context": state,
    }

    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            N8N_WEBHOOK,
            json=payload,
        )

        resp.raise_for_status()

        data = resp.json()

    return {
        **state,
        "answer": data.get(
            "answer",
            "Workflow executado com sucesso."
        ),
    }