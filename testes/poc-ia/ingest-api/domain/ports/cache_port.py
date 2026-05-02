from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

class CachePort(ABC):
    @abstractmethod
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def set(self, key: str, value: Dict[str, Any], ttl: int) -> None:
        pass
