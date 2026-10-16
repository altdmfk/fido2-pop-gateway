from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # JWT & Credential Security
    secret_key: str = "super-secret-mock-key-for-dev-32bytes"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    timestamp_tolerance_seconds: int = 60
    max_credentials_per_user: int = 20

    # Nonce Store Configuration
    nonce_ttl_seconds: int = 60
    nonce_cleanup_interval_seconds: int = 30
    nonce_max_entries: int = 50000

    # Rate Limiter Configuration
    rate_limit_requests: int = 10
    rate_limit_window_seconds: float = 1.0
    rate_limit_max_tracked_ips: int = 10000

    # Upstream Reverse Proxy Configuration
    upstream_url: str = "http://localhost:8080"
    upstream_connect_timeout: float = 5.0
    upstream_read_timeout: float = 30.0
    upstream_write_timeout: float = 10.0
    upstream_pool_timeout: float = 5.0
    upstream_max_connections: int = 200
    upstream_max_keepalive_connections: int = 50
    spooled_body_max_size_bytes: int = 1024 * 1024  # 1MB in-memory buffer before spooling to disk

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
