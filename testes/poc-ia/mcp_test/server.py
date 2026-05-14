from fastmcp import FastMCP

# Cria o servidor MCP
mcp = FastMCP("Meu Servidor MCP")

# --- Ferramentas (Tools) ---

@mcp.tool()
def somar(a: float, b: float) -> float:
    """Soma dois números."""
    return a + b

@mcp.tool()
def saudacao(nome: str) -> str:
    """Retorna uma saudação personalizada."""
    return f"Olá, {nome}! Bem-vindo ao servidor MCP."

# --- Recursos (Resources) ---

@mcp.resource("info://servidor")
def info_servidor() -> str:
    """Informações sobre o servidor."""
    return "FastMCP rodando com suporte a qualquer origem."

# --- Inicialização ---

if __name__ == "__main__":
    app = mcp.http_app()
    for route in app.routes:
        print(route.path, getattr(route, 'methods', 'N/A'))

    mcp.run(
        transport="sse",
        host="0.0.0.0",
        port=8000,
    )