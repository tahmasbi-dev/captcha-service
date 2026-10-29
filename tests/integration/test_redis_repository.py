"""Integration tests: RedisChallengeRepository against real Redis.

These are the tests that pin the concurrency guarantees down in a
repeatable way (previously only ad-hoc scripts proved them).
"""
import asyncio
import datetime as dt
import hashlib
from datetime import timedelta

import pytest
from redis.asyncio import Redis

from captcha_service.domain.entities.challenge import Challenge
from captcha_service.domain.exceptions import StaleChallenge
from captcha_service.domain.value_objects.action import Action
from captcha_service.domain.value_objects.challenge_id import ChallengeId
from captcha_service.domain.value_objects.solve_outcome import SolveOutcome
from captcha_service.infrastructure.redis_challenge_repository import RedisChallengeRepository

NOW = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.timezone.utc)


def make_repo(redis: Redis) -> RedisChallengeRepository:
    return RedisChallengeRepository(redis, grace=timedelta(seconds=120))


async def issue_new(repo: RedisChallengeRepository, solution: str = "ABC123", action: str = "login",
                    ttl: timedelta = timedelta(minutes=5)) -> Challenge:
    challenge = Challenge.issue(
        action=Action.from_str(action), solution=solution, now=NOW, ttl=ttl,
    )
    await repo.save(challenge)
    return challenge


# ---- save / get round trip ----
async def test_save_and_get_round_trips_all_fields(redis: Redis):
    repo = make_repo(redis)
    challenge = await issue_new(repo)

    loaded = await repo.get(challenge.id)
    assert loaded is not None
    assert str(loaded.id) == str(challenge.id)
    assert loaded.state == challenge.state
    assert loaded.proof.solution_hash == challenge.proof.solution_hash
    assert loaded.proof.action == challenge.proof.action
    assert loaded._version == 1                                # rehydrated with the stored version
    assert loaded.expires_at == challenge.expires_at


async def test_get_returns_none_for_absent_id(redis: Redis):
    repo = make_repo(redis)
    assert await repo.get(ChallengeId.new()) is None


async def test_save_with_stale_version_raises_and_leaves_row_intact(redis: Redis):
    repo = make_repo(redis)
    challenge = await issue_new(repo)
    stale_snapshot = await repo.get(challenge.id)

    # legit writer advances the row
    stale_snapshot_again = await repo.get(challenge.id)
    await repo.save(stale_snapshot_again)

    # the now-stale snapshot must lose
    with pytest.raises(StaleChallenge):
        await repo.save(stale_snapshot)
    assert (await repo.get(challenge.id))._version == 2


async def test_double_insert_is_a_cas_loss(redis: Redis):
    repo = make_repo(redis)
    first = await issue_new(repo)
    second = await issue_new(repo, solution="ZZZ")
    _ = second
    # Re-saving `first` with expected_version 0 (fresh insert) must collide
    # with the existing row instead of overwriting it.
    first._version = 0
    first._state = first.state
    with pytest.raises(StaleChallenge):
        await repo.save(first)


# ---- concurrency: save herd ----
async def test_50_concurrent_saves_of_a_fresh_challenge_produce_exactly_one_winner(redis: Redis):
    """50 writers all try to INSERT the same identity (expected_version 0).

    The CAS script only lets the first one through; the other 49 lose
    and raise StaleChallenge. This is what protects against duplicate
    challenge rows under identical-key races.
    """
    repo = make_repo(redis)
    cid = ChallengeId.new()

    async def contestant() -> bool:
        challenge = Challenge.issue(
            action=Action.from_str("login"), solution="ABC123", now=NOW, ttl=timedelta(minutes=5),
        )
        challenge.id = cid
        try:
            await repo.save(challenge)
            return True
        except StaleChallenge:
            return False

    outcomes = list(await asyncio.gather(*[contestant() for _ in range(50)]))
    assert outcomes.count(True) == 1, f"expected exactly one winner, got {outcomes.count(True)}"
    assert outcomes.count(False) == 49


# ---- attempt_solve: single-shot semantics ----
async def _solve_digest(solution: str) -> str:
    return hashlib.sha256(solution.encode()).hexdigest()


async def test_attempt_solve_full_state_ladder(redis: Redis):
    repo = make_repo(redis)
    cid = ChallengeId.new()
    action = Action.from_str("login")
    sha = await _solve_digest("ABC123")

    challenge = Challenge.issue(action=action, solution="ABC123", now=NOW, ttl=timedelta(minutes=5))
    challenge.id = cid
    await repo.save(challenge)

    assert await repo.attempt_solve(cid, action, "wrong-digest", now=NOW) == SolveOutcome.WRONG
    assert await repo.attempt_solve(cid, action, sha, now=NOW) == SolveOutcome.NOT_SOLVABLE  # burned

    # fresh one: correct solve, then idempotent solve again with no version churn
    challenge2 = await issue_new(repo)
    assert await repo.attempt_solve(
        challenge2.id, action, await _solve_digest("ABC123"), now=NOW
    ) == SolveOutcome.SOLVED
    version_after_first = (await repo.get(challenge2.id))._version
    assert await repo.attempt_solve(
        challenge2.id, action, await _solve_digest("ABC123"), now=NOW
    ) == SolveOutcome.ALREADY_SOLVED
    assert (await repo.get(challenge2.id))._version == version_after_first

    # expired-in-place
    challenge3 = await issue_new(repo, ttl=timedelta(minutes=1))
    later = NOW + timedelta(minutes=2)
    assert await repo.attempt_solve(
        challenge3.id, action, await _solve_digest("ABC123"), now=later
    ) == SolveOutcome.EXPIRED

    # unknown id
    assert await repo.attempt_solve(
        ChallengeId.new(), action, sha, now=NOW
    ) == SolveOutcome.NOT_FOUND


async def test_attempt_solve_under_herd_exactly_one_solve_result(redis: Redis):
    repo = make_repo(redis)
    challenge = await issue_new(repo)
    sha = await _solve_digest("ABC123")

    outcomes = await asyncio.gather(*[
        repo.attempt_solve(challenge.id, Action.from_str("login"), sha, now=NOW)
        for _ in range(30)
    ])
    assert outcomes.count(SolveOutcome.SOLVED) == 1
    assert outcomes.count(SolveOutcome.ALREADY_SOLVED) == 29   # everyone after the winner still succeeds
    assert (await repo.get(challenge.id)).state.value == "solved"


async def test_attempt_solve_wrong_answer_burns_under_herd(redis: Redis):
    repo = make_repo(redis)
    challenge = await issue_new(repo)

    outcomes = await asyncio.gather(*[
        repo.attempt_solve(challenge.id, Action.from_str("login"), await _solve_digest(f"guess-{i}"), now=NOW)
        for i in range(20)
    ])
    assert set(outcomes) == {SolveOutcome.WRONG, SolveOutcome.NOT_SOLVABLE}
    assert outcomes.count(SolveOutcome.NOT_SOLVABLE) >= 1      # at least one arrived after the burn
    assert (await repo.get(challenge.id)).state.value == "failed"


# ---- expiry index ----
async def test_find_due_for_expiry_returns_only_issued_overdue_challenges(redis: Redis):
    repo = make_repo(redis)
    overdue = await issue_new(repo, solution="DUE1", ttl=timedelta(minutes=1))
    on_time = await issue_new(repo, solution="ONTIME", ttl=timedelta(minutes=30))

    due = await repo.find_due_for_expiry(NOW + timedelta(minutes=2))
    due_ids = [str(c.id) for c in due]
    assert str(overdue.id) in due_ids
    assert str(on_time.id) not in due_ids
    assert [str(c.id) for c in due] == [str(overdue.id)]        # ordered oldest first


async def test_find_due_for_expiry_drops_orphans_from_the_index(redis: Redis):
    repo = make_repo(redis)
    challenge = await issue_new(repo, ttl=timedelta(minutes=1))

    # Terminal transition removes it from the zset via the CAS path...
    later = NOW + timedelta(minutes=2)
    await repo.attempt_solve(challenge.id, Action.from_str("login"), await _solve_digest("ABC123"), now=later)
    assert await repo.find_due_for_expiry(later) == []


async def test_solve_correct_answer_writes_expiry_index_removal(redis: Redis):
    repo = make_repo(redis)
    challenge = await issue_new(repo)
    await repo.attempt_solve(challenge.id, Action.from_str("login"), await _solve_digest("ABC123"), now=NOW)
    now_ts = dt.datetime.now(dt.timezone.utc).timestamp()
    remaining = await redis.zrangebyscore("challenge:expiry", "-inf", now_ts + 600)
    assert str(challenge.id) not in remaining
