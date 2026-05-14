from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.schemas import ChatCompletionRequest
from app.graph import graph
from app.integrations.mcp_client import mcp
from app.config import get_logger

logger = get_logger(__name__)

# ---------------------------------
# startup / shutdown
# ---------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Inicializando agent-gateway...")

    # conecta no MCP e mantém SSE aberto
    await mcp.connect()

    logger.info("agent-gateway pronto.")

    yield

    logger.info("Encerrando agent-gateway...")
    await mcp.client.aclose()


app = FastAPI(
    title="Agent Gateway",
    lifespan=lifespan,
)


# ---------------------------------
# health
# ---------------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}


# ---------------------------------
# openai compatibility
# ---------------------------------
@app.get("/v1/models")
async def models():
    return {
        "object": "list",
        "data": [
            {
                "id": "enterprise-agent",
                "object": "model",
                "owned_by": "company",
            }
        ],
    }


# ---------------------------------
# chat completions
# ---------------------------------
@app.post("/v1/chat/completions")
async def chat(req: ChatCompletionRequest):
    user_message = req.messages[-1].content

    state = {
        "question": user_message,
        "route": None,
        "tool": None,
        "tool_args": None,
        "tool_result": None,
        "answer": None,
    }

    result = await graph.ainvoke(state)

    answer = result["answer"]

    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": answer,
                },
                "finish_reason": "stop",
            }
        ],
    }