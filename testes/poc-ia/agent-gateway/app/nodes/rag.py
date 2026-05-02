from app.integrations.ollama import llm
from app.integrations.vector import search_vector

async def rag_node(state: dict):
    """
    Recupera contexto no Vector DB e usa o LLM para responder a pergunta baseada no contexto.
    """
    question = state["question"]

    print("[RAG NODE] searching context for:", question)
    
    # Busca contexto no banco vetorial
    context = await search_vector(question)

    if not context:
        print("[RAG NODE] no context found. Fallback to LLM standard answer.")
        response = await llm.ainvoke(question)
        return {
            **state,
            "answer": response.content,
        }

    print("[RAG NODE] context found. Generating answer...")
    
    prompt = f"""Você é um assistente útil e preciso. Responda à pergunta do usuário baseando-se EXCLUSIVAMENTE no contexto fornecido abaixo. Se o contexto não tiver a resposta, diga que não sabe, não invente informações.

Contexto:
{context}

Pergunta:
{question}
"""

    response = await llm.ainvoke(prompt)

    return {
        **state,
        "answer": response.content,
    }
