from typing import Optional

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# A secret under this many characters is brute-forcible at boot, not at rest.
_MIN_SECRET_CHARS = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="CAPTCHA_",
        case_sensitive=False,
        extra="forbid",          # typo in .env → crash at startup, not silent default
    )

    internal_api_key: SecretStr
    # Previous internal key, during a rotation window. While set, both the
    # current and the previous value authenticate: callers that have not
    # been redeployed with the new key keep working, and you drop the
    # old one after every caller has switched.
    internal_api_key_prev: Optional[SecretStr] = None
    
    # ---- Redis ----
    # Explicit IPv4 loopback: `localhost` can double-resolve (::1/127.0.0.1)
    # and split a connection pool across two different Redis servers.
    redis_url: str = "redis://127.0.0.1:6379/0"
    redis_grace_seconds: int = 600

    # Socket-level ceilings for every Redis call. Without them a wedged
    # Redis or a black-hole network stalls handlers indefinitely.
    redis_socket_connect_timeout: float = 2.0
    redis_socket_timeout: float = 2.0

    # Seconds between expiry sweeps that flip overdue ISSUED challenges to
    # expired and keep the expiry sorted set bounded. 0 disables the
    # sweeper entirely (expiry then relies on Redis TTLs alone).
    expiry_sweep_interval_seconds: int = 60

    # ---- JWT ----
    # Symmetric mode (default): HS256 and jwt_secret — fine while this
    # service is the only holder of the key, because it both issues and
    # verifies. Asymmetric mode: set jwt_algorithm to RS256 or EdDSA and
    # provide PEMs for both keys. Then jwt_secret is ignored, and a
    # remote resource server that verifies tokens needs ONLY the public
    # key — it cannot mint tokens even if it is fully compromised.
    jwt_secret: Optional[SecretStr] = None
    jwt_private_key_pem: Optional[SecretStr] = None
    jwt_public_key_pem: Optional[SecretStr] = None
    jwt_issuer: str = "captcha-service"
    jwt_algorithm: str = "HS256"                                     # HS256/HS384/HS512 | RS256 | EdDSA
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

    # ---- Rate limiting (per client IP, token bucket, state in Redis) ----
    # 0 disables the limiter entirely.
    rate_limit_enabled: bool = True
    # Challenge issuance: the expensive endpoint (PNG render per hit).
    challenge_rate_max: int = 15          # bucket size = burst allowance
    challenge_rate_per_seconds: int = 15  # refill rate = sustained rate
    # Solve attempts: cheap (one Lua call) but brute-force fuel.
    solve_rate_max: int = 30
    solve_rate_per_seconds: int = 10
    # Verify is internal-only (X-Internal-Key), so no public limiter.

    @field_validator("internal_api_key", "internal_api_key_prev", "jwt_secret")
    @classmethod
    def _secrets_must_be_nontrivial(cls, v: Optional[SecretStr]) -> Optional[SecretStr]:
        """A short secret is a launch-day brute-force target, so fail at boot.

        Length is the practical proxy here: entropy per char is env
        specific, but nothing a human picked or a template shipped is
        32+ random characters. Generate with `openssl rand -hex 32`.
        """
        if v is None:
            return v
        value = v.get_secret_value()
        if len(value) < _MIN_SECRET_CHARS:
            raise ValueError(
                f"secret too weak: must be at least {_MIN_SECRET_CHARS} chars "
                f"(got {len(value)}); generate with `openssl rand -hex 32`"
            )
        return v

    @model_validator(mode="after")
    def _jwt_keys_must_match_algorithm(self) -> "Settings":
        """Fail fast when the key material does not suit the algorithm."""
        if self.jwt_algorithm.startswith("HS"):
            if self.jwt_secret is None:
                raise ValueError("jwt_secret is required for HS* algorithms")
        else:
            if self.jwt_private_key_pem is None:
                raise ValueError(f"jwt_private_key_pem is required for {self.jwt_algorithm}")
            if self.jwt_public_key_pem is None:
                raise ValueError(f"jwt_public_key_pem is required for {self.jwt_algorithm} (verifiers get this one)")
        return self

    @field_validator("redis_url")
    @classmethod
    def _redis_url_must_carry_schema(cls, v: str) -> str:
        if not v.startswith(("redis://", "rediss://", "unix://")):
            raise ValueError("redis_url must be redis://, rediss:// or unix://")
        return v