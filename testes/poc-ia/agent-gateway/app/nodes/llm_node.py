import os
from langchain_ollama import ChatOllama


MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")


llm = ChatOllama(
    model=MODEL,
    base_url=OLLAMA_URL,
    temperature=0,
)


async def llm_node(state: dict):
    """
    Resposta normal do LLM
    """

    question = state["question"]

    print("[LLM NODE] answering...")

    response = await llm.ainvoke(question)

    return {
        **state,
        "answer": response.content,
    }