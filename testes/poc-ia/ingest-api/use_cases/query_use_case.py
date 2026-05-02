import time
import hashlib
from typing import Dict, Any

from domain.ports.cache_port import CachePort
from domain.ports.metrics_port import MetricsPort
from domain.ports.embedder_port import EmbedderPort
from domain.ports.vector_store_port import VectorStorePort
from core.config import settings

class QueryUseCase:
    def __init__(
        self,
        cache: CachePort,
        metrics: MetricsPort,
        embedder: EmbedderPort,
        vector_store: VectorStorePort
    ):
        self.cache = cache
        self.metrics = metrics
        self.embedder = embedder
        self.vector_store = vector_store

    def _hash_key(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    def _build_context(self, results) -> str:
        return "\n\n".join(
            f"Fonte: {r['metadata']}\n{r['chunk']}"
            for r in results
        )

    def execute(self, question: str) -> Dict[str, Any]:
        start_total = time.time()
        cache_key = f"query:{self._hash_key(question)}"

        # 1. CACHE HIT
        cached = self.cache.get(cache_key)
        if cached:
            self.metrics.inc("cache_hit")
            self.metrics.timing("query_total", start_total)
            return {
                **cached,
                "source": "cache"
            }

        self.metrics.inc("cache_miss")

        # 2. EMBEDDING
        t0 = time.time()
        vector = self.embedder.embed(question)
        self.metrics.timing("embedding_latency", t0)

        # 3. VECTOR SEARCH
        t1 = time.time()
        results = self.vector_store.search_vector(vector)
        self.metrics.timing("vector_search_latency", t1)

        # 4. CONTEXT BUILD
        context = self._build_context(results)

        response = {
            "question": question,
            "context": context,
            "sources": results,
            "source": "fresh"
        }

        # 5. CACHE WRITE (TTL)
        self.cache.set(cache_key, response, settings.CACHE_TTL)

        # 6. MÉTRICAS
        self.metrics.timing("query_total", start_total)
        self.metrics.inc("queries_total")

        return response
