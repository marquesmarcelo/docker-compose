import os
import json
import psycopg
from langchain_ollama import OllamaEmbeddings

# Embeddings Configuration
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")

embeddings_model = OllamaEmbeddings(
    model=EMBED_MODEL,
    base_url=OLLAMA_URL
)

# Database Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://agent:agent123@alloydb:5432/agentdb")

async def search_vector(query: str, top_k: int = 3, min_score: float = 0.25) -> str:
    """
    Realiza a busca vetorial no PostgreSQL usando a query informada.
    Retorna o contexto concatenado como texto.
    """
    # 1. Obter o embedding da query
    vector = await embeddings_model.aembed_query(query)
    
    # 2. Conectar ao banco e pesquisar
    results = []
    try:
        # Usando psycopg de forma síncrona temporariamente 
        # (Idealmente usaria psycopg.AsyncConnection, mas manteremos simples por compatibilidade)
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT chunk, (embedding <=> %s::vector) AS distance
                    FROM rag.documents
                    ORDER BY distance
                    LIMIT %s;
                    """,
                    (json.dumps(vector), top_k)
                )
                rows = cur.fetchall()
                
                for r in rows:
                    chunk = r[0]
                    distance = float(r[1])
                    if distance < min_score:
                        results.append(chunk)
    except Exception as e:
        print(f"[VECTOR] Erro ao buscar: {e}")
        return ""
    
    # Se não filtrou nenhum pelo score mínimo, mas tem retorno, pode voltar os melhores
    if not results and rows:
        results = [r[0] for r in rows[:2]]
        
    if not results:
        return ""
        
    return "\n\n".join(results)
