from abc import ABC, abstractmethod

class MetricsPort(ABC):
    @abstractmethod
    def inc(self, metric: str) -> None:
        pass

    @abstractmethod
    def timing(self, metric: str, duration: float) -> None:
        pass
