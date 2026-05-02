import json
import psycopg
from typing import List, Dict, Any

from domain.ports.vector_store_port import VectorStorePort

class PostgresVectorStore(VectorStorePort):
    def __init__(self, db_url: str):
        self.db_url = db_url

    def save_chunk(self, content: str, embedding: List[float], metadata: Dict[str, Any]) -> None:
        with psycopg.connect(self.db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO rag.documents
                    (chunk, embedding, metadata)
                    VALUES (%s, %s, %s)
                    """,
                    (
                        content,
                        json.dumps(embedding),
                        json.dumps(metadata)
                    )
                )
            conn.commit()

    def search_vector(self, vector: List[float], top_k: int = 5, min_score: float = 0.25) -> List[Dict[str, Any]]:
        with psycopg.connect(self.db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT chunk, metadata, (embedding <=> %s::vector) AS distance
                    FROM rag.documents
                    ORDER BY distance
                    LIMIT %s;
                    """,
                    (json.dumps(vector), top_k)
                )
                rows = cur.fetchall()

        results = [
            {
                "chunk": r[0],
                "metadata": r[1],
                "distance": float(r[2])
            }
            for r in rows
        ]

        filtered = [r for r in results if r["distance"] < min_score]
        return filtered if filtered else results[:2]
