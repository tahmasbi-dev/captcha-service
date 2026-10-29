from __future__ import annotations

import hashlib

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from redis.asyncio import Redis
from redis.exceptions import RedisError

from captcha_service.application.ports.metrics import UsageMetrics
from captcha_service.domain.value_objects.redemption import RedemptionOutcome


# ---- instruments ----------------------------------------------------------
REQUEST_LATENCY = Histogram(
    "captcha_http_request_duration_seconds",
    "Endpoint latency, labelled by method, route template and status code.",
    ["method", "path", "status"],
)
REDIS_ERRORS = Counter(
    "captcha_redis_errors_total",
    "Redis operations that failed while serving a request.",
)
STALE_CHALLENGES = Counter(
    "captcha_stale_challenge_writes_total",
    "CAS saves that lost the optimistic-concurrency race.",
)
EXPIRY_QUEUED = Gauge(
    "captcha_challenges_awaiting_expiry",
    "Challenges currently indexed in the expiry sorted set.",
)
SWEEP_EXPIRED = Counter(
    "captcha_challenges_expired_total",
    "Challenges flipped to expired by the background sweeper.",
)
REDEEM_OUTCOMES = Counter(
    "captcha_redeem_outcomes_total",
    "Verify outcomes: new, replay, conflict, not_found.",
    ["outcome"],
)
SOLVE_RESULTS = Counter(
    "captcha_solve_results_total",
    "Solve submissions judged right or wrong.",
    ["result"],
)


class PrometheusUsageMetrics(UsageMetrics):
    def record_redeem(self, outcome: RedemptionOutcome) -> None:
        REDEEM_OUTCOMES.labels(outcome=outcome.value).inc()

    def record_solve(self, solved: bool) -> None:
        SOLVE_RESULTS.labels(result="right" if solved else "wrong").inc()


# ---- helpers used by the API layer ----------------------------------------
def record_redis_error() -> None:
    REDIS_ERRORS.inc()


def record_stale_challenge() -> None:
    STALE_CHALLENGES.inc()


def expiries_swept(count: int) -> None:
    if count:
        SWEEP_EXPIRED.inc(count)


def request_latency(method: str, path_template: str, status: int, seconds: float) -> None:
    REQUEST_LATENCY.labels(method=method, path=path_template, status=str(status)).observe(seconds)


def render_metrics() -> tuple[bytes, str]:
    """The Prometheus text format payload plus its content type."""
    return generate_latest(), CONTENT_TYPE_LATEST


# ---- health bookkeeping ----------------------------------------------------
# Lua scripts live as module constants in their adapters; the SHAs here
# must match what register_script computes, i.e. a plain sha1 of the
# source text.
_SCRIPTS: dict[str, str] = {}


def register_script_name(name: str, source: str) -> None:
    _SCRIPTS[name] = hashlib.sha1(source.encode("utf-8")).hexdigest()


async def refresh_expiry_gauge(redis: Redis) -> None:
    """Snapshot how many challenges are still waiting in the expiry index.

    The metrics endpoint calls this just before rendering, so each
    Prometheus scrape carries a fresh number. If Redis is down the
    gauge keeps its last value and the failure lands in redis_errors_total.
    """
    try:
        EXPIRY_QUEUED.set(await redis.zcard("challenge:expiry"))
    except RedisError:
        REDIS_ERRORS.inc()


async def redis_healthcheck(redis: Redis) -> dict:
    """Ping Redis and check the registered scripts are still cached.

    A missing script doesn't have to be fatal (asyncio Script objects
    reload themselves when Redis says NOSCRIPT), but it tells you the
    Redis was recently wiped or points somewhere else, so the health
    output says so.
    """
    try:
        await redis.ping()
        results = await redis.script_exists(*_SCRIPTS.values())
    except RedisError as exc:
        REDIS_ERRORS.inc()
        return {"redis_up": False, "error": type(exc).__name__, "scripts": {}}
    return {
        "redis_up": True,
        "error": None,
        "scripts": {name: bool(ok) for name, ok in zip(_SCRIPTS, results)},
    }
