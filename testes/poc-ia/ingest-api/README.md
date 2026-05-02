# Configuração no OpenWebUI

1. Clique em `workspace` -> `Tools` -> `New Tool`

2. Na aba de código copie o código abaixo:
```python
"""
title: API RAG Search
author: Antigravity
version: 1.0.0
description: Uma ferramenta para buscar documentos internos da empresa utilizando nossa Ingestion API.
"""

import requests


class Tools:
    def __init__(self):
        # A URL da nossa API FastAPI.
        # ATENÇÃO: Se o Open WebUI estiver rodando em Docker e a API estiver em outro container/host,
        # adapte essa URL para o host correto (ex: http://api:8000 ou http://host.docker.internal:8000)
        self.api_url = "http://ingest-api:8000"

    def query_internal_documents(self, question: str) -> str:
        """
        Acione esta ferramenta sempre que o usuário fizer perguntas sobre processos internos,
        documentos da empresa, PDFs ou assuntos que necessitem de conhecimento corporativo.

        :param question: A pergunta do usuário que será buscada na base de conhecimento.
        :return: Uma string contendo o contexto recuperado dos documentos para ajudar a responder.
        """
        try:
            response = requests.post(
                f"{self.api_url}/query", json={"question": question}, timeout=200
            )

            response.raise_for_status()

            data = response.json()
            context = data.get("context", "")

            if not context:
                return (
                    "A busca não encontrou resultados relevantes na base de documentos."
                )

            resultado_final = (
                "## Contexto Extraído dos Documentos:\n"
                f"{context}\n\n"
                "Instrução ao LLM: Utilize o contexto acima para responder à pergunta do usuário. "
                "Cite as fontes mencionadas no contexto."
            )
            
            return resultado_final

        except Exception as e:
            return f"Erro ao acessar a base de documentos interna: {str(e)}"
```

4. Em `Tool Name` digite `RAG API Search` e em `Tool Description` digite `RAG API Search`

5. Agora clique em `Models` -> `New Model`. No formulário preencha:
* `Model Name`: `Rag Model`
* `Base Model (From)`: `qwen2.5:3b`
* `Tools`: marque `RAG API Search`

6. Clique em `Save & Create`