from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    api_key: str = ""
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
    sarvam_api_key: str = ""
    debug_mode: bool = False

    redis_sentinel_enabled: bool = False
    redis_sentinel_hosts: str = "sentinel-0:26379,sentinel-1:26379,sentinel-2:26379"
    redis_sentinel_master: str = "scamintelli-master"
    redis_pool_min: int = 10
    redis_pool_max: int = 100
    redis_retry_attempts: int = 3
    redis_retry_delay: float = 0.5
    redis_socket_timeout: float = 5.0
    redis_socket_connect_timeout: float = 5.0

    distributed_lock_ttl: int = 30
    distributed_lock_retry_count: int = 3
    distributed_lock_retry_delay: float = 0.2

    task_queue_stream: str = "scamintelli:tasks"
    task_queue_dlq_stream: str = "scamintelli:dlq"
    task_queue_consumer_group: str = "scamintelli-workers"
    task_queue_max_retries: int = 3
    task_queue_visibility_timeout: int = 60
    task_queue_batch_size: int = 10

    worker_callback_enabled: bool = True
    worker_graph_enabled: bool = True
    worker_fingerprint_enabled: bool = True
    worker_concurrency: int = 4

    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_recovery_timeout: int = 30
    circuit_breaker_half_open_max: int = 3

    backpressure_max_queue_depth: int = 500
    backpressure_shed_threshold: float = 0.9
    backpressure_slowdown_threshold: float = 0.7

    graph_cache_ttl: int = 300
    graph_batch_interval: int = 60
    graph_max_nodes: int = 50000
    graph_computation_timeout: int = 30

    neo4j_enabled: bool = True
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    neo4j_max_pool_size: int = 50
    neo4j_connection_timeout: float = 5.0

    @property
    def is_production(self) -> bool:
        return not self.debug_mode and self.enable_tamper_protection

    @property
    def sentinel_host_list(self) -> List[tuple]:
        hosts = []
        for entry in self.redis_sentinel_hosts.split(","):
            entry = entry.strip()
            if ":" in entry:
                host, port = entry.rsplit(":", 1)
                hosts.append((host, int(port)))
            else:
                hosts.append((entry, 26379))
        return hosts


@lru_cache()
def get_settings() -> Settings:
    return Settings()


def reload_settings() -> Settings:
    get_settings.cache_clear()
    return get_settings()
