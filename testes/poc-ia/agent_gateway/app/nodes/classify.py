async def classify_node(state):
    question = state["question"].lower()

    if any(x in question for x in ["servidor", "status", "srv-"]):
        intent = "mcp"

    elif any(x in question for x in ["abrir chamado", "ticket", "workflow"]):
        intent = "workflow"

    elif any(x in question for x in ["norma", "documento", "manual"]):
        intent = "rag"

    else:
        intent = "chat"

    return {
        **state,
        "intent": intent
    }