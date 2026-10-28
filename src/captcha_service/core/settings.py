from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="CAPTCHA_",
        case_sensitive=False,
        extra="forbid",          # typo in .env → crash at startup, not silent default
    )

    internal_api_key: SecretStr
    
    # ---- Redis ----
    # Explicit IPv4 loopback: `localhost` can double-resolve (::1/127.0.0.1)
    # and split a connection pool across two different Redis servers.
    redis_url: str = "redis://127.0.0.1:6379/0"
    redis_grace_seconds: int = 600

    # Seconds between expiry sweeps that flip overdue ISSUED challenges to
    # expired and keep the expiry sorted set bounded. 0 disables the
    # sweeper entirely (expiry then relies on Redis TTLs alone).
    expiry_sweep_interval_seconds: int = 60

    # ---- JWT (secret is REQUIRED — no default, fail fast) ----
    jwt_secret: SecretStr
    jwt_issuer: str = "captcha-service"
    jwt_algorithm: str = "HS256"
    token_ttl_seconds: int = 300

    # ---- Redemption (single-use verification) ----
    # How long a successful verdict is kept on file for idempotent retries.
    # Must stay shorter than token_ttl_seconds: a retry with an already-
    # expired token is rejected as expired, record or no record.
    redemption_retention_seconds: int = 120

    # ---- CAPTCHA ----
    challenge_ttl_seconds: int = 300
    captcha_length: int = 6
    captcha_width: int = 280
    captcha_height: int = 90