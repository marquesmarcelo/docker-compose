from abc import ABC, abstractmethod
from typing import List

class EmbedderPort(ABC):
    @abstractmethod
    def embed(self, text: str) -> List[float]:
        pass
