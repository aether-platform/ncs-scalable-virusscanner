from pydantic_settings import BaseSettings


class RedisSettings(BaseSettings):
    host: str = "localhost"
    port: int = 6379


class FlagsmithSettings(BaseSettings):
    env_key: str | None = None
