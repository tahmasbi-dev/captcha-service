"""Integration tests: RedisProofLedger + token-bucket limiter + expiry sweeper."""
import asyncio
import datetime as dt
import uuid
from datetime import timedelta

import pytest

from captcha_service.domain.value_objects.action import Action
from captcha_service.domain.value_objects.challenge_id import ChallengeId
from captcha_service.infrastructure.expiry_sweeper import ExpirySweeper
from captcha_service.infrastructure.proof_ledger import RedisProofLedger
from captcha_service.infrastructure.rate_limiter import RateLimitExceeded, RedisTokenBucketLimiter
from captcha_service.infrastructure.redis_challenge_repository import RedisChallengeRepository

NOW = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.timezone.utc)


def make_ledger(redis) -> RedisProofLedger:
    return RedisProofLedger(redis, retention_seconds=120)


async def _seed_solved_challenge(redis, cid: str) -> None:
    await redis.hset(f"challenge:{cid}", mapping={"id": cid, "state": "solved", "action": "login"})
    await redis.zadd("challenge:expiry", {cid: NOW.timestamp()})


# ---- ProofLedger ----
async def test_redeem_new_then_replay_then_hard_miss(redis):
    ledger = make_ledger(redis)
    cid = str(uuid.uuid4())
    await _seed_solved_challenge(redis, cid)

    first = await ledger.redeem(ChallengeId.from_str(cid), Action.from_str("login"), "token-1")
    assert first.value == "new"
    assert not await redis.exists(f"challenge:{cid}")   # challenge consumed on first redemption

    second = await ledger.redeem(ChallengeId.from_str(cid), Action.from_str("login"), "token-1")
    assert second.value == "replay"                    # one same-token retry still lands

    third = await ledger.redeem(ChallengeId.from_str(cid), Action.from_str("login"), "token-1")
    assert third.value == "not_found"                  # after that it is a definitive miss


async def test_redeem_conflict_when_a_different_token_arrives(redis):
    ledger = make_ledger(redis)
    cid = str(ChallengeId.new())
    await _seed_solved_challenge(redis, cid)

    first = await ledger.redeem(ChallengeId.from_str(cid), Action.from_str("login"), "token-1")
    assert first.value == "new"

    conflict = await ledger.redeem(ChallengeId.from_str(cid), Action.from_str("login"), "token-2")
    assert conflict.value == "conflict"


async def test_redeem_not_found_without_solved_challenge(redis):
    ledger = make_ledger(redis)
    outcome = await ledger.redeem(ChallengeId.new(), Action.from_str("login"), "token-1")
    assert outcome.value == "not_found"


async def test_redeem_same_token_herd_every_call_succeeds_exactly_one_new(redis):
    ledger = make_ledger(redis)
    cid = str(ChallengeId.new())
    await _seed_solved_challenge(redis, cid)

    results = list(await asyncio.gather(*[
        ledger.redeem(ChallengeId.from_str(cid), Action.from_str("login"), "same-token")
        for _ in range(16)
    ]))
    values = [r.value for r in results]
    assert values.count("new") == 1
    # the record replays exactly once: 1 new + 1 same-token replay win,
    # every later caller in the herd is a hard miss, not a second pass
    assert values.count("replay") == 1
    assert values.count("not_found") == 14
    assert "conflict" not in values


async def test_redeem_different_tokens_herd_single_winner(redis):
    ledger = make_ledger(redis)
    cid = str(ChallengeId.new())
    await _seed_solved_challenge(redis, cid)

    results = list(await asyncio.gather(*[
        ledger.redeem(ChallengeId.from_str(cid), Action.from_str("login"), f"token-{i}")
        for i in range(16)
    ]))
    values = [r.value for r in results]
    assert values.count("new") == 1
    assert values.count("conflict") == 15


async def test_two_lexicographically_different_verification_paths_use_only_redeem_keys(redis):
    """Nothing outside the documented key namespaces is ever written."""
    ledger = make_ledger(redis)
    cid = str(ChallengeId.new())
    await _seed_solved_challenge(redis, cid)
    before = sorted(await redis.keys("*"))
    await ledger.redeem(ChallengeId.from_str(cid), Action.from_str("login"), "token-1")
    after = sorted(await redis.keys("*"))
    # challenge hash and expiry zset are both gone (empty zset self-deletes);
    # only the redemption record remains
    assert after == [f"redemption:{cid}"]


# ---- rate limiter ----
class _Peer:
    """Minimal stand-in for a starlette Request: only .client.host is read."""

    def __init__(self, host: str) -> None:
        self.client = self
        self._host = host

    @property
    def host(self) -> str:
        return self._host


async def test_token_bucket_allows_burst_then_429(redis):
    limiter = RedisTokenBucketLimiter(name="t-bucket-a", capacity=3, refill_per_second=1, redis=redis)
    req = _Peer("11.11.11.11")

    for _ in range(3):
        await limiter.check(req)
    with pytest.raises(RateLimitExceeded):
        await limiter.check(req)


async def test_token_bucket_is_per_ip(redis):
    limiter = RedisTokenBucketLimiter(name="t-bucket-b", capacity=2, refill_per_second=1, redis=redis)

    await limiter.check(_Peer("10.0.0.1"))
    await limiter.check(_Peer("10.0.0.1"))
    with pytest.raises(RateLimitExceeded):
        await limiter.check(_Peer("10.0.0.1"))
    await limiter.check(_Peer("10.0.0.2"))   # independent budget


async def test_token_bucket_fails_open_when_redis_dies(redis):
    limiter = RedisTokenBucketLimiter(name="t-bucket-c", capacity=2, refill_per_second=1, redis=redis)

    async def explode(*args, **kwargs):
        raise ConnectionError("redis down")

    limiter._bucket = explode
    await limiter.check(_Peer("10.0.0.3"))   # must NOT raise


async def test_bucket_refills_over_time(redis):
    import time
    limiter = RedisTokenBucketLimiter(name="t-bucket-d", capacity=2, refill_per_second=50, redis=redis)
    req = _Peer("10.0.0.4")

    await limiter.check(req)
    await limiter.check(req)
    with pytest.raises(RateLimitExceeded):
        await limiter.check(req)
    time.sleep(0.05)                          # 50/s refill ⇒ ~2.5 tokens back
    await limiter.check(req)                  # affordable again


# ---- expiry sweeper ----
async def test_sweeper_flips_only_truly_overdue_challenges(redis):
    from captcha_service.domain.entities.challenge import Challenge

    repo = RedisChallengeRepository(redis, grace=timedelta(seconds=60))

    # the sweeper's clock sits 30 minutes after issue; only the short-TTL
    # challenge is overdue by then
    overdue = Challenge.issue(
        action=Action.from_str("login"), solution="ABC123", now=NOW, ttl=timedelta(minutes=5),
    )
    alive = Challenge.issue(
        action=Action.from_str("login"), solution="DEADOI", now=NOW, ttl=timedelta(hours=2),
    )

    sweep_now = NOW + timedelta(minutes=30)

    class _SweepClock:
        def now(self):
            return sweep_now

    await repo.save(overdue)
    await repo.save(alive)

    sweeper = ExpirySweeper(repo=repo, clock=_SweepClock(), interval=timedelta(seconds=60))
    expired_count = await sweeper.sweep_once()

    assert expired_count == 1
    swept = await repo.get(overdue.id)
    assert swept.state.value == "expired"

    alive_loaded = await repo.get(alive.id)
    assert alive_loaded is not None and alive_loaded.state.value == "issued"
