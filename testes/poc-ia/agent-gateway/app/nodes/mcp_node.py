from app.integrations.mcp_client import mcp


async def mcp_node(state: dict):
    """
    Executa tools MCP quando o planner decidir.
    """

    tool_name = state.get("tool")
    tool_args = state.get("tool_args", {})

    if not tool_name:
        return {
            **state,
            "tool_result": None,
        }

    print(f"[MCP NODE] calling tool={tool_name} args={tool_args}")

    result = await mcp.call_tool(
        tool_name,
        tool_args,
    )

    print("[MCP NODE] result =", result)

    return {
        **state,
        "tool_result": result,
    }