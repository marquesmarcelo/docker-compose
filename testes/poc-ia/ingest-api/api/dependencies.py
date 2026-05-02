import redis
from fastapi import Depends
from core.config import settings

from domain.ports.cache_port import CachePort
from domain.ports.metrics_port import MetricsPort
from domain.ports.embedder_port import EmbedderPort
from domain.ports.vector_store_port import VectorStorePort

from infrastructure.cache.redis_cache import RedisCache
from infrastructure.metrics.redis_metrics import RedisMetrics
from infrastructure.embedder.ollama_embedder import OllamaEmbedder
from infrastructure.database.postgres_vector_store import PostgresVectorStore

from use_cases.ingest_use_case import IngestUseCase
from use_cases.query_use_case import QueryUseCase

# Global Redis instance to reuse connection pool
_redis_client = redis.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, decode_responses=True)

def get_redis_client() -> redis.Redis:
    return _redis_client

def get_cache_port(redis_client: redis.Redis = Depends(get_redis_client)) -> CachePort:
    return RedisCache(redis_client)

def get_metrics_port(redis_client: redis.Redis = Depends(get_redis_client)) -> MetricsPort:
    return RedisMetrics(redis_client)

def get_embedder_port() -> EmbedderPort:
    return OllamaEmbedder(settings.OLLAMA_URL, settings.EMBED_MODEL)

def get_vector_store_port() -> VectorStorePort:
    return PostgresVectorStore(settings.db_url)

def get_ingest_use_case(
    embedder: EmbedderPort = Depends(get_embedder_port),
    vector_store: VectorStorePort = Depends(get_vector_store_port)
) -> IngestUseCase:
    return IngestUseCase(embedder, vector_store)

def get_query_use_case(
    cache: CachePort = Depends(get_cache_port),
    metrics: MetricsPort = Depends(get_metrics_port),
    embedder: EmbedderPort = Depends(get_embedder_port),
    vector_store: VectorStorePort = Depends(get_vector_store_port)
) -> QueryUseCase:
    return QueryUseCase(cache, metrics, embedder, vector_store)
