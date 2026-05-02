from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.schemas import ChatCompletionRequest
from app.agent import ask_agent
from app.mcp_client import ensure_connected


# ---------------------------------------------------
# STARTUP / SHUTDOWN
# ---------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Inicializando LLM Gateway...")

    # conecta no MCP Hub uma única vez
    await ensure_connected()

    print("LLM Gateway pronto.")

    yield

    print("Encerrando LLM Gateway...")


# ---------------------------------------------------
# APP
# ---------------------------------------------------
app = FastAPI(
    title="LLM Gateway",
    lifespan=lifespan
)


# ---------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------
@app.get("/health")
async def health():
    return {
        "status": "ok"
    }


# ---------------------------------------------------
# OPENAI-COMPATIBLE /v1/models
# ---------------------------------------------------
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


# ---------------------------------------------------
# OPENAI-COMPATIBLE /v1/chat/completions
# ---------------------------------------------------
@app.post("/v1/chat/completions")
async def chat_completion(req: ChatCompletionRequest):
    """
    Endpoint compatível com OpenAI API.
    OpenWebUI conversa aqui.
    LangChain decide:
      - usar MCP tool
      - ou responder via Ollama
    """

    # pega última mensagem do usuário
    user_message = req.messages[-1].content

    # chama agent
    response = await ask_agent(user_message)

    # devolve formato OpenAI
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": response
                },
                "finish_reason": "stop"
            }
        ]
    }