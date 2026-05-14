from app.integrations.ollama import llm
from app.config import get_logger

logger = get_logger(__name__)

async def llm_node(state: dict):
    """
    Resposta normal do LLM
    """
    question = state["question"]

    logger.info("[LLM NODE] answering...")

    response = await llm.ainvoke(question)

    return {
        **state,
        "answer": response.content,
    }