-- Habilita pgvector
CREATE EXTENSION IF NOT EXISTS vector;

-- Schema do RAG
CREATE SCHEMA IF NOT EXISTS rag;

-- Tabela vetorial
CREATE TABLE IF NOT EXISTS rag.documents (
    id BIGSERIAL PRIMARY KEY,
    chunk TEXT,
    embedding VECTOR(768),
    metadata JSONB,
    created_at TIMESTAMP DEFAULT now()
);

-- índice vetorial (performance)
CREATE INDEX IF NOT EXISTS idx_rag_embedding
ON rag.documents
USING hnsw (embedding vector_cosine_ops);