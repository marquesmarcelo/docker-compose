import json
import psycopg
from langchain_ollama import OllamaEmbeddings

from app.config import settings, get_logger

logger = get_logger(__name__)

# Embeddings Configuration
embeddings_model = OllamaEmbeddings(
    model=settings.EMBED_MODEL,
    base_url=settings.OLLAMA_URL
)

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
        # Usando psycopg de forma assíncrona
        async with await psycopg.AsyncConnection.connect(settings.DATABASE_URL) as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT chunk, (embedding <=> %s::vector) AS distance
                    FROM rag.documents
                    ORDER BY distance
                    LIMIT %s;
                    """,
                    (json.dumps(vector), top_k)
                )
                rows = await cur.fetchall()
                
                for r in rows:
                    chunk = r[0]
                    distance = float(r[1])
                    if distance < min_score:
                        results.append(chunk)
                        
    except Exception as e:
        logger.error(f"Erro ao buscar vetores: {e}", exc_info=True)
        return ""
    
    # Se não filtrou nenhum pelo score mínimo, mas tem retorno, pode voltar os melhores
    if not results and rows:
        results = [r[0] for r in rows[:2]]
        
    if not results:
        return ""
        
    return "\n\n".join(results)
