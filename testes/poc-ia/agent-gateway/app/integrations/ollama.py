from langchain_ollama import ChatOllama
from app.config import settings

llm = ChatOllama(
    model=settings.MODEL_NAME,
    base_url=settings.OLLAMA_URL,
    temperature=0
)