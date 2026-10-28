# application/bootstrap.py
from dataclasses import dataclass
from datetime import timedelta

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
from captcha_service.infrastructure.redis_challenge_images import RedisChallengeImageStore
from captcha_service.infrastructure.redis_challenge_repository import RedisChallengeRepository


@dataclass(frozen=True, slots=True)
class UseCases:
    get_new_challenge: GetNewChallenge
    solve_challenge: SolveChallenge
    verify_token: VerifyToken
    get_challenge_image: GetChallengeImage


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
    tokens = JwtTokenService(
        secret=settings.jwt_secret.get_secret_value().encode(),
        issuer=settings.jwt_issuer,
        algorithm=settings.jwt_algorithm,
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
