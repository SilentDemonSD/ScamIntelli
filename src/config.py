from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    api_key: str = "default_api_key"
    gemini_api_key: str = ""
    guvi_callback_url: str = ""
    redis_url: str = "redis://localhost:6379"
    use_redis: bool = False
    log_level: str = "INFO"
    session_timeout_seconds: int = 3600
    max_engagement_turns: int = 15
    scam_threshold: float = 0.7


@lru_cache()
def get_settings() -> Settings:
    return Settings()
