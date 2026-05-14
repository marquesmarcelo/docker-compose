from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # Banco de Dados
    DB_HOST: str = "alloydb"
    DB_NAME: str = "agentdb"
    DB_USER: str = "agent"
    DB_PASSWORD: str = "agent123"

    # Redis
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379

    # Modelos (Ollama)
    OLLAMA_URL: str = "http://ollama:11434"
    EMBED_MODEL: str = "nomic-embed-text"

    # Configurações da Aplicação
    CACHE_TTL: int = 3600
    UPLOAD_DIR: str = "/tmp"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @property
    def db_url(self) -> str:
        return f"host={self.DB_HOST} dbname={self.DB_NAME} user={self.DB_USER} password={self.DB_PASSWORD}"

settings = Settings()
