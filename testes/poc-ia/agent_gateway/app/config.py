import logging
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # LLM Settings
    OLLAMA_URL: str = "http://ollama:11434"
    MODEL_NAME: str = "qwen2.5:3b"
    EMBED_MODEL: str = "nomic-embed-text"

    # Database Settings
    DATABASE_URL: str = "postgresql://agent:agent123@alloydb:5432/agentdb"

    # External Integrations
    MCP_URL: str = "http://mcp-hub:8000"
    N8N_WEBHOOK: str = "http://n8n:5678/webhook/agent"

    # Logging Settings
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()

# Configure logging application-wide
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
