import json
from typing import Optional, Dict, Any
import redis

from domain.ports.cache_port import CachePort

class RedisCache(CachePort):
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        value = self.redis.get(key)
        return json.loads(value) if value else None

    def set(self, key: str, value: Dict[str, Any], ttl: int) -> None:
        self.redis.setex(key, ttl, json.dumps(value))
