from typing import Dict, Any
from domain.ports.embedder_port import EmbedderPort
from domain.ports.vector_store_port import VectorStorePort
from use_cases.utils.loader import load_pdf
from use_cases.utils.splitter import split_docs

class IngestUseCase:
    def __init__(self, embedder: EmbedderPort, vector_store: VectorStorePort):
        self.embedder = embedder
        self.vector_store = vector_store

    def _extract_metadata(self, doc) -> Dict[str, Any]:
        return {
            "source": doc.metadata.get("source"),
            "page": doc.metadata.get("page"),
            "type": "pdf"
        }

    def execute(self, file_path: str) -> Dict[str, Any]:
        docs = load_pdf(file_path)
        chunks = split_docs(docs)

        count = 0

        for chunk in chunks:
            vector = self.embedder.embed(chunk.page_content)
            metadata = self._extract_metadata(chunk)

            self.vector_store.save_chunk(chunk.page_content, vector, metadata)
            count += 1

        return {
            "chunks": count,
            "status": "ok"
        }
