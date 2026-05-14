from app.integrations.mcp_client import mcp
from app.config import get_logger

logger = get_logger(__name__)

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

    logger.info(f"[MCP NODE] calling tool={tool_name} args={tool_args}")

    try:
        result = await mcp.call_tool(
            tool_name,
            tool_args,
        )
        logger.debug(f"[MCP NODE] result = {result}")
    except Exception as e:
        logger.error(f"[MCP NODE] erro ao chamar tool: {e}", exc_info=True)
        result = None

    return {
        **state,
        "tool_result": result,
    }