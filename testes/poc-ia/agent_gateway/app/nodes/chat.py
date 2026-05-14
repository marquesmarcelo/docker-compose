from app.integrations.ollama import llm


async def chat_node(state):
    response = await llm.ainvoke(state["question"])

    return {
        **state,
        "answer": response.content
    }