import os
from langchain_ollama import ChatOllama

OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://ollama:11434"
)

llm = ChatOllama(
    model="qwen2.5:3b",
    base_url=OLLAMA_URL,
    temperature=0
)