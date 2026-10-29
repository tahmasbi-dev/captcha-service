from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from fastapi import HTTPException, Request, status

from redis.asyncio import Redis

from captcha_service.infrastructure import observability

log = logging.getLogger(__name__)


class RateLimitExceeded(HTTPException):
    def __init__(self, retry_after: int) -> None:
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="rate limit exceeded",
            headers={"Retry-After": str(max(int(retry_after), 1))},
        )


@dataclass(frozen=True)
class RateLimitPolicy:
    """One token bucket; one policy per (endpoint class, client ip).

    max = burst capacity, per_seconds = sustained refill rate. Keeping
    them separate means a client cannot bank tokens like a plain
    windowed counter would allow.
    """

    name: str
    max: int
    per_seconds: int


# One shared Lua script: the whole bucket check-and-decrement is a single
# Redis operation, so N workers against one Redis still enforce one
# bucket per (policy, ip) — no cross-process races.
#
#   KEYS[1] = <policy>:<ip>
#   ARGV[1] = capacity          ARGV[2] = refill per second
#   ARGV[3] = now ((ms precision float seconds))
#   ARGV[4] = cost
#
# returns {allowed 0|1, remaining_tokens, retry_after_ms}
_TOKEN_BUCKET = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

local state = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts = tonumber(state[2])
if tokens == nil or ts == nil then
  tokens = capacity
  ts = now
end

local elapsed = math.max(now - ts, 0)
tokens = math.min(tokens + elapsed * refill, capacity)

local allowed = 0
local retry_after = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  retry_after = math.ceil((cost - tokens) / refill * 1000)
end

tokens = math.max(tokens, 0)
redis.call('HSET', key, 'tokens', tokens, 'ts', now)
local ttl = math.ceil(capacity / refill * 2) + 1
redis.call('EXPIRE', key, ttl)
return {allowed, tokens, retry_after}
"""


def client_ip(request: Request) -> str:
    """The socket peer, deliberately NOT X-Forwarded-For.

    A public endpoint trusting an attacker-set header hands every
    anonymous client an unlimited supply of buckets. When a real proxy
    is deployed, that proxy normalizes/strips XFF and sets its own
    header; switch to it here, not to raw XFF.
    """
    if request.client is None or not request.client.host:
        return "unknown"
    return request.client.host


class RedisTokenBucketLimiter:
    """Per-IP token buckets backed by the redis we already use.

    One instance per endpoint policy. Buckets live in short-TTL keys
    (`<name>:{ip}`), so idle clients cost nothing and a restart forgets
    only who was near their limit. A Redis outage fails the limiter
    *open* — availability first for a captcha service whose whole job
    is to not be the reason login breaks — and the failure is counted
    in the redis_errors metric like any other.
    """

    def __init__(
        self,
        *,
        name: str,
        capacity: int,
        refill_per_second: int,
        redis: Redis | None = None,
    ) -> None:
        self._name = name
        self._capacity = max(int(capacity), 1)
        self._refill = max(int(refill_per_second), 1)
        self._redis = redis
        self._bucket = redis.register_script(_TOKEN_BUCKET) if redis is not None else None

    def bind(self, redis: Redis) -> "RedisTokenBucketLimiter":
        """Attach the live client (routes get it via Depends())."""
        if self._redis is redis:
            return self
        clone = RedisTokenBucketLimiter(
            name=self._name,
            capacity=self._capacity,
            refill_per_second=self._refill,
            redis=redis,
        )
        return clone

    async def check(self, request: Request, cost: int = 1) -> None:
        limiter = self
        redis = self._redis
        if redis is None:
            # Not bound yet — pull the app-level client lazily.
            redis = limiter._redis or request.app.state.redis
            limiter = RedisTokenBucketLimiter(
                name=self._name,
                capacity=self._capacity,
                refill_per_second=self._refill,
                redis=redis,
            )
        try:
            result = await limiter._bucket(
                keys=[f"ratelimit:{limiter._name}:{client_ip(request)}"],
                args=[limiter._capacity, limiter._refill, time.time(), cost],
            )
        except Exception:
            # Metric it, log it, and let the request through: the limiter
            # must never be the single point that takes the service down.
            observability.record_redis_error()
            log.exception("rate limiter redis failure; failing open")
            return None

        allowed, _remaining, retry_ms = result
        if not allowed:
            raise RateLimitExceeded(retry_after=float(retry_ms) / 1000.0)
