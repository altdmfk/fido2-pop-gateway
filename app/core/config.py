from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    secret_key: str = "super-secret-mock-key-for-dev-32bytes"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    upstream_url: str = "http://localhost:8080"

    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
