import httpx
from app.config import OLLAMA_URL, DEFAULT_MODEL

async def call_ollama(messages, model=None):

    model = model or DEFAULT_MODEL

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": model,
                "messages": messages,
                "stream": False
            }
        )

    data = resp.json()

    print("OLLAMA RESPONSE:", data)

    # 🔥 compatibilidade com versões diferentes
    if "message" in data:
        return data["message"]["content"]

    if "response" in data:
        return data["response"]

    return str(data)