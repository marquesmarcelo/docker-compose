import requests
from typing import List

from domain.ports.embedder_port import EmbedderPort

class OllamaEmbedder(EmbedderPort):
    def __init__(self, ollama_url: str, model_name: str):
        self.ollama_url = ollama_url
        self.model_name = model_name

    def embed(self, text: str) -> List[float]:
        response = requests.post(
            f"{self.ollama_url}/api/embeddings",
            json={
                "model": self.model_name,
                "prompt": text
            },
            timeout=120
        )
        response.raise_for_status()
        return response.json()["embedding"]
