from typing import Optional

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Anything shorter than this is realistically guessable, so we
# refuse to boot with such a secret.
_MIN_SECRET_CHARS = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="CAPTCHA_",
        case_sensitive=False,
        extra="forbid",          # typo in .env should crash at startup, not silently apply defaults
    )

    internal_api_key: SecretStr
    # The previous internal key during a rotation window. While it is
    # set, both values authenticate, so callers that haven't picked up
    # the new key keep working. Clear it once everyone has switched.
    internal_api_key_prev: Optional[SecretStr] = None
    
    # ---- Redis ----
    # Explicit IPv4 loopback. On Windows `localhost` resolves to both
    # ::1 and 127.0.0.1, which can split one pool across two addresses.
    redis_url: str = "redis://127.0.0.1:6379/0"
    redis_grace_seconds: int = 600

    # Socket-level ceilings on every Redis call. Without them a wedged
    # Redis can leave handlers hanging forever.
    redis_socket_connect_timeout: float = 2.0
    redis_socket_timeout: float = 2.0

    # Seconds between expiry sweeps, which flip overdue issued
    # challenges and keep the expiry sorted set bounded. Set to 0 to
    # turn the sweeper off (expiry then relies on Redis TTLs alone).
    expiry_sweep_interval_seconds: int = 60

    # ---- JWT ----
    # Symmetric mode (the default): HS256 plus jwt_secret. That's fine
    # while this service holds the key and both issues and verifies.
    # For asymmetric mode, set jwt_algorithm to RS256 or EdDSA and
    # provide the PEMs. jwt_secret is then ignored, and a remote
    # verifier only needs the public key, which means it can't mint
    # tokens even if it's fully compromised.
    jwt_secret: Optional[SecretStr] = None
    jwt_private_key_pem: Optional[SecretStr] = None
    jwt_public_key_pem: Optional[SecretStr] = None
    jwt_issuer: str = "captcha-service"
    jwt_algorithm: str = "HS256"                                     # HS256/HS384/HS512 | RS256 | EdDSA
    token_ttl_seconds: int = 300

    # ---- Redemption (single-use verification) ----
    # How long a verdict stays on file for idempotent retries. It has
    # to be shorter than token_ttl_seconds: a retry whose token has
    # already expired is rejected as expired, record or no record.
    redemption_retention_seconds: int = 120

    # ---- CAPTCHA ----
    challenge_ttl_seconds: int = 300
    captcha_length: int = 6
    captcha_width: int = 280
    captcha_height: int = 90

    # ---- Rate limiting (per client IP, token bucket, state in Redis) ----
    # 0 disables the limiter entirely.
    rate_limit_enabled: bool = True
    # Challenge issuance, the expensive endpoint (a PNG render per hit).
    challenge_rate_max: int = 15          # bucket size = burst allowance
    challenge_rate_per_seconds: int = 15  # refill rate = sustained rate
    # Solve attempts: cheap per call, but useful for brute-forcing.
    solve_rate_max: int = 30
    solve_rate_per_seconds: int = 10
    # Verify is internal-only (X-Internal-Key), so no public limiter.

    @field_validator("internal_api_key", "internal_api_key_prev", "jwt_secret")
    @classmethod
    def _secrets_must_be_nontrivial(cls, v: Optional[SecretStr]) -> Optional[SecretStr]:
        """Refuse to boot with a short secret.

        Length is a crude stand-in for entropy, but a useful one: a
        secret worth typing by hand, or that ships in a template, is
        not 32+ random characters.
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
        """Fail fast when the provided keys don't suit the algorithm."""
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