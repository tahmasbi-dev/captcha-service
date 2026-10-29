# application/bootstrap.py
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from redis.asyncio import Redis

from captcha_service.application.use_cases.get_challenge_image import GetChallengeImage
from captcha_service.application.use_cases.get_new_challenge import GetNewChallenge
from captcha_service.application.use_cases.solve_challenge import SolveChallenge
from captcha_service.application.use_cases.verify_token import VerifyToken
from captcha_service.core.settings import Settings
from captcha_service.infrastructure.clock import SystemClock
from captcha_service.infrastructure.expiry_sweeper import ExpirySweeper
from captcha_service.infrastructure.image_captcha_generator import ImageCaptchaGenerator
from captcha_service.infrastructure.jwt_token_service import JwtTokenService
from captcha_service.infrastructure.observability import PrometheusUsageMetrics
from captcha_service.infrastructure.proof_ledger import RedisProofLedger
from captcha_service.infrastructure.rate_limiter import RedisTokenBucketLimiter
from captcha_service.infrastructure.redis_challenge_images import RedisChallengeImageStore
from captcha_service.infrastructure.redis_challenge_repository import RedisChallengeRepository


@dataclass(frozen=True, slots=True)
class UseCases:
    get_new_challenge: GetNewChallenge
    solve_challenge: SolveChallenge
    verify_token: VerifyToken
    get_challenge_image: GetChallengeImage


@dataclass(frozen=True, slots=True)
class Limiters:
    """Token-bucket policies, one per public endpoint class.

    Issuance is capped tighter than solving: a render costs CPU on us,
    a solve costs one Lua call. Verify stays internal-key only, so it
    gets no public bucket.
    """

    challenges: Optional[RedisTokenBucketLimiter]
    solves: Optional[RedisTokenBucketLimiter]


def build_limiters(*, redis: Redis, settings: Settings) -> Limiters:
    """Token buckets share the request Redis pool; KeyError-free on rebuild."""
    if not settings.rate_limit_enabled:
        return Limiters(challenges=None, solves=None)
    return Limiters(
        challenges=RedisTokenBucketLimiter(
            name="challenges",
            capacity=settings.challenge_rate_max,
            refill_per_second=settings.challenge_rate_per_seconds,
            redis=redis,
        ),
        solves=RedisTokenBucketLimiter(
            name="solves",
            capacity=settings.solve_rate_max,
            refill_per_second=settings.solve_rate_per_seconds,
            redis=redis,
        ),
    )


def build_use_cases(*, redis: Redis, settings: Settings) -> UseCases:
    repo = RedisChallengeRepository(
        redis,
        grace=timedelta(seconds=settings.redis_grace_seconds),
    )
    captcha = ImageCaptchaGenerator(
        width=settings.captcha_width,
        height=settings.captcha_height,
        length=settings.captcha_length,
    )
    clock = SystemClock()
    if settings.jwt_algorithm.startswith("HS"):
        tokens = JwtTokenService(
            secret=settings.jwt_secret.get_secret_value().encode(),
            issuer=settings.jwt_issuer,
            algorithm=settings.jwt_algorithm,
        )
    else:
        tokens = JwtTokenService(
            issuer=settings.jwt_issuer,
            algorithm=settings.jwt_algorithm,
            private_key_pem=settings.jwt_private_key_pem.get_secret_value(),
            public_key_pem=settings.jwt_public_key_pem.get_secret_value(),
        )
    ledger = RedisProofLedger(
        redis,
        retention_seconds=settings.redemption_retention_seconds,
    )
    images = RedisChallengeImageStore(redis)
    usage_metrics = PrometheusUsageMetrics()

    # Image bytes must survive as long as the challenge itself: TTL +
    # grace, the same window the challenge hash gets.
    image_ttl = timedelta(
        seconds=settings.challenge_ttl_seconds + settings.redis_grace_seconds,
    )

    return UseCases(
        get_new_challenge=GetNewChallenge(
            repo=repo,
            captcha=captcha,
            clock=clock,
            ttl=timedelta(seconds=settings.challenge_ttl_seconds),
            images=images,
            image_ttl=image_ttl,
        ),
        solve_challenge=SolveChallenge(
            repo=repo,
            tokens=tokens,
            clock=clock,
            token_ttl=timedelta(seconds=settings.token_ttl_seconds),
            metrics=usage_metrics,
        ),
        verify_token=VerifyToken(verifier=tokens, ledger=ledger, metrics=usage_metrics),
        get_challenge_image=GetChallengeImage(images=images),
    )


def build_expiry_sweeper(*, redis: Redis, settings: Settings) -> ExpirySweeper:
    """Own repo/clock instances; the sweeper runs its own loop.

    A second repository instance is a couple of objects and a shared
    script set - everything it needs already lives on the pool.
    """
    return ExpirySweeper(
        repo=RedisChallengeRepository(
            redis,
            grace=timedelta(seconds=settings.redis_grace_seconds),
        ),
        clock=SystemClock(),
        interval=timedelta(seconds=settings.expiry_sweep_interval_seconds),
    )
