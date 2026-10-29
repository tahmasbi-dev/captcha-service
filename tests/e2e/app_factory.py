"""Build a fully wired app instance in-process (what lifespan does).

ASGITransport does not run lifespan events, so tests build the same
state manually: one namespace per instance for isolation.
"""
from dataclasses import dataclass, field
from typing import Optional

from redis.asyncio import Redis

from captcha_service.api.app import create_app
from captcha_service.application.bootstrap import Limiters, build_limiters, build_use_cases
from captcha_service.core.settings import Settings
from captcha_service.infrastructure.rate_limiter import RedisTokenBucketLimiter


def make_settings(prefix: str = "tst", **overrides) -> Settings:
    kwargs = {
        "internal_api_key": (prefix + "-internal") * 8,          # >= 32 chars
        "jwt_secret": (prefix + "-jwt-secret") * 6 + "x",        # >= 32 chars
        "_env_file": None,
    }
    kwargs.update(overrides)
    return Settings(**kwargs)


def key_prefix_for(tag: str) -> str:
    return f"challenge-{tag}"


@dataclass
class BuiltApp:
    app: object
    redis: Redis
    settings: Settings
    prefix: str


async def build_app(
    url: str,
    *,
    tag: str,
    settings: Optional[Settings] = None,
    challenge_repo_prefix: str = "challenge",
) -> BuiltApp:
    """An isolated app: db-2 redis, own key strings, custom buckets allowed."""
    redis = Redis.from_url(url, decode_responses=True)
    settings = settings or make_settings(prefix=f"{tag}-prefix")
    app = create_app()
    app.state.settings = settings
    app.state.redis = redis
    app.state.use_cases = build_use_cases(redis=redis, settings=settings)
    app.state.limiters = build_limiters(redis=redis, settings=settings)
    return BuiltApp(app=app, redis=redis, settings=settings, prefix=challenge_repo_prefix)


async def build_tight_limiter_app(url: str, *, tag: str, capacity: int) -> BuiltApp:
    """Same factory but with deliberately small buckets, for 429 tests."""
    redis = Redis.from_url(url, decode_responses=True)
    settings = make_settings(prefix=f"{tag}-tight")
    app = create_app()
    app.state.settings = settings
    app.state.redis = redis
    app.state.use_cases = build_use_cases(redis=redis, settings=settings)
    app.state.limiters = Limiters(
        challenges=RedisTokenBucketLimiter(
            name=f"challenges-{tag}", capacity=capacity, refill_per_second=1, redis=redis,
        ),
        solves=RedisTokenBucketLimiter(
            name=f"solves-{tag}", capacity=capacity, refill_per_second=1, redis=redis,
        ),
    )
    return BuiltApp(app=app, redis=redis, settings=settings, prefix="challenge")
