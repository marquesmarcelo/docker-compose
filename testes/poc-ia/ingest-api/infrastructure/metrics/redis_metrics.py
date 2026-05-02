import redis
import time
from domain.ports.metrics_port import MetricsPort

class RedisMetrics(MetricsPort):
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    def inc(self, metric: str) -> None:
        self.redis.incr(f"metrics:{metric}")

    def timing(self, metric: str, duration: float) -> None:
        self.redis.lpush(f"metrics:{metric}:latency", duration)
        self.redis.ltrim(f"metrics:{metric}:latency", 0, 1000)
