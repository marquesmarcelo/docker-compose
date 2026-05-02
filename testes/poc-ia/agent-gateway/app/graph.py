from typing import TypedDict, Optional, Dict, Any

from langgraph.graph import StateGraph, END

from app.nodes.planner import planner_node
from app.nodes.mcp_node import mcp_node
from app.nodes.llm_node import llm_node
from app.nodes.n8n_node import n8n_node
from app.nodes.rag import rag_node


class AgentState(TypedDict):
    question: str
    route: Optional[str]
    tool: Optional[str]
    tool_args: Optional[Dict[str, Any]]
    tool_result: Optional[Any]
    answer: Optional[str]


def router(state: AgentState):
    route = state["route"]

    print(f"[GRAPH] route={route}")

    if route == "mcp":
        return "mcp"

    if route == "n8n":
        return "n8n"

    if route == "rag":
        return "rag"

    return "llm"


def finalize_from_mcp(state: AgentState):
    """
    Converte resposta MCP em texto final.
    """

    result = state.get("tool_result")

    if not result:
        return {
            **state,
            "answer": "Nenhum resultado encontrado.",
        }

    # MCP padrão
    if "content" in result:
        content = result["content"]

        if isinstance(content, list) and len(content):
            first = content[0]

            if isinstance(first, dict):
                text = first.get("text")

                if text:
                    return {
                        **state,
                        "answer": text,
                    }

    return {
        **state,
        "answer": str(result),
    }


graph_builder = StateGraph(AgentState)

# nodes
graph_builder.add_node("planner", planner_node)
graph_builder.add_node("mcp", mcp_node)
graph_builder.add_node("llm", llm_node)
graph_builder.add_node("n8n", n8n_node)
graph_builder.add_node("rag", rag_node)
graph_builder.add_node("finalize_mcp", finalize_from_mcp)

# entrypoint
graph_builder.set_entry_point("planner")

# planner routing
graph_builder.add_conditional_edges(
    "planner",
    router,
    {
        "mcp": "mcp",
        "n8n": "n8n",
        "rag": "rag",
        "llm": "llm",
    },
)

# edges
graph_builder.add_edge("mcp", "finalize_mcp")
graph_builder.add_edge("finalize_mcp", END)

graph_builder.add_edge("n8n", END)
graph_builder.add_edge("rag", END)
graph_builder.add_edge("llm", END)

graph = graph_builder.compile()