import os

# -----------------------------
# OLLAMA
# -----------------------------
OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://ollama:11434"
)

DEFAULT_MODEL = os.getenv(
    "DEFAULT_MODEL",
    "qwen2.5:3b"
)

# -----------------------------
# MCP
# -----------------------------
MCP_URL = os.getenv(
    "MCP_URL",
    "http://mcp-hub:8000"
)

MCP_SSE_ENDPOINT = f"{MCP_URL}/sse"

# endpoint base (session_id será acrescentado)
MCP_MESSAGES_ENDPOINT = f"{MCP_URL}/messages"


# -----------------------------
# GATEWAY
# -----------------------------
APP_NAME = os.getenv(
    "APP_NAME",
    "LLM Gateway Enterprise"
)

LOG_LEVEL = os.getenv(
    "LOG_LEVEL",
    "INFO"
)

REQUEST_TIMEOUT = float(
    os.getenv(
        "REQUEST_TIMEOUT",
        "60"
    )
)