import hmac
from typing import Annotated, Optional

from fastapi import Depends, Header, HTTPException, Request, status
from redis.asyncio import Redis

from captcha_service.application.bootstrap import UseCases
from captcha_service.core.settings import Settings


def get_use_cases(request: Request) -> UseCases:
    return request.app.state.use_cases


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_redis(request: Request) -> Redis:
    return request.app.state.redis


UseCasesDep = Annotated[UseCases, Depends(get_use_cases)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
RedisDep = Annotated[Redis, Depends(get_redis)]


def require_internal_key(
    settings: SettingsDep,
    x_internal_key: Annotated[Optional[str], Header(alias="X-Internal-Key")] = None,
) -> None:
    # While internal_api_key_prev is set, both the current and the old
    # key authenticate. Move callers over to the new key first, then
    # clear the old one; rotating with this overlap avoids a redeploy
    # window where both sides disagree.
    accepted = [settings.internal_api_key.get_secret_value()]
    if settings.internal_api_key_prev is not None:
        accepted.append(settings.internal_api_key_prev.get_secret_value())
    presented = x_internal_key if x_internal_key is not None else "\x00missing\x00"  # can never match
    if not any(hmac.compare_digest(presented, k) for k in accepted):
        # Wrong key and missing key get the same response on purpose.
        # Details leak would only help whoever is guessing.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="unauthorized")


InternalOnly = Depends(require_internal_key)


# ---- per-IP rate limiting on the public endpoints --------------------------
#
# The buckets live in Redis, on the same client everything else uses,
# so workers share one budget per client instead of each getting their
# own. Empty bucket -> 429 with Retry-After.

from captcha_service.application.bootstrap import Limiters  # noqa: E402


def get_limiters(request: Request) -> Limiters:
    return request.app.state.limiters


LimitersDep = Annotated[Limiters, Depends(get_limiters)]


async def limit_challenges(request: Request, limiters: LimitersDep) -> None:
    """429 gate on POST /challenges, the CPU-heavy endpoint."""
    if limiters.challenges is not None:
        await limiters.challenges.check(request)


async def limit_solves(request: Request, limiters: LimitersDep) -> None:
    """429 gate on POST /solve. Cheap per call, but brute-force fuel."""
    if limiters.solves is not None:
        await limiters.solves.check(request)


ChallengeRateLimit = Depends(limit_challenges)
SolveRateLimit = Depends(limit_solves)