import os
from langchain_ollama import ChatOllama

llm = ChatOllama(
    model=os.getenv("MODEL_NAME", "qwen2.5:3b"),
    base_url=os.getenv("OLLAMA_URL", "http://ollama:11434"),
    temperature=0
)