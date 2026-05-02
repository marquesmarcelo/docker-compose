from langchain_core.tools import tool
from app.mcp_client import call_tool


@tool
async def verificar_status_servidor(id_servidor: str) -> str:
    """
    Consulta status de um servidor pelo ID.
    Exemplo: srv-01, srv-02
    """
    return await call_tool(
        "verificar_status_servidor",
        {"id_servidor": id_servidor}
    )


@tool
async def listar_inventario_completo() -> str:
    """
    Lista todos os ativos cadastrados.
    """
    return await call_tool(
        "listar_inventario_completo",
        {}
    )


# export para LangChain
tools = [
    verificar_status_servidor,
    listar_inventario_completo,
]