from fastapi import FastAPI
from api.routers import ingest_router, query_router

app = FastAPI(
    title="RAG Ingestion API",
    description="API para ingestão e consulta de documentos usando RAG.",
    version="1.0.0"
)

app.include_router(ingest_router.router, tags=["Ingestion"])
app.include_router(query_router.router, tags=["Query"])