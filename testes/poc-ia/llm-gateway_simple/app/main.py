from fastapi import FastAPI
from app.schemas import ChatCompletionRequest
from app.ollama import call_ollama
from app.router import route

app = FastAPI(title="LLM Gateway")


# -----------------------------
# HEALTH
# -----------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}


# -----------------------------
# OPENAI /models
# -----------------------------
@app.get("/v1/models")
async def list_models():
    return {
        "object": "list",
        "data": [
            {
                "id": "qwen2.5:3b",
                "object": "model",
                "owned_by": "gateway"
            }
        ]
    }


# -----------------------------
# CHAT
# -----------------------------
@app.post("/v1/chat/completions")
async def chat_completion(req: ChatCompletionRequest):

    messages = [
        {"role": m.role, "content": m.content}
        for m in req.messages
    ]

    # tenta MCP primeiro
    tool_response = await route(messages)

    if tool_response:
        response = tool_response
    else:
        response = await call_ollama(
            messages=messages,
            model=req.model
        )

    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": response
                }
            }
        ]
    }