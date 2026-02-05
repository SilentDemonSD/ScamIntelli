from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    api_key: str = "default_api_key"
    gemini_api_key: str = ""
    guvi_callback_url: str = ""
    redis_url: str = "redis://localhost:6379"
    use_redis: bool = False
    log_level: str = "INFO"
    session_timeout_seconds: int = 3600
    max_engagement_turns: int = 15
    scam_threshold: float = 0.7
    response_delay_min: float = 0.5
    response_delay_max: float = 2.5
    enable_tamper_protection: bool = True
    max_concurrent_sessions: int = 1000
    rate_limit_per_minute: int = 60
    debug_mode: bool = False

    @property
    def is_production(self) -> bool:
        return not self.debug_mode and self.enable_tamper_protection


@lru_cache()
def get_settings() -> Settings:
    return Settings()


def reload_settings() -> Settings:
    get_settings.cache_clear()
    return get_settings()
