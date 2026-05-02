from abc import ABC, abstractmethod
from typing import List, Dict, Any

class VectorStorePort(ABC):
    @abstractmethod
    def save_chunk(self, content: str, embedding: List[float], metadata: Dict[str, Any]) -> None:
        pass

    @abstractmethod
    def search_vector(self, vector: List[float], top_k: int = 5, min_score: float = 0.25) -> List[Dict[str, Any]]:
        pass
