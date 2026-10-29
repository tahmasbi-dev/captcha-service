from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Sequence

from redis.asyncio import Redis

from captcha_service.domain.entities.challenge import Challenge
from captcha_service.domain.ports.challenge_repository import ChallengeRepository
from captcha_service.domain.exceptions import DomainError, StaleChallenge
from captcha_service.domain.value_objects.action import Action
from captcha_service.domain.value_objects.challenge_id import ChallengeId
from captcha_service.domain.value_objects.proof import Proof
from captcha_service.domain.value_objects.solve_outcome import SolveOutcome
from captcha_service.domain.value_objects.state import State

from captcha_service.infrastructure import observability


CAS_SAVE_LUA = """
-- KEYS[1] = challenge:{id}   (hash)
-- KEYS[2] = challenge:expiry (sorted set)
-- ARGV[1] = expected_version (0 = insert)
-- ARGV[2] = new_version
-- ARGV[3] = expires_at score (unix seconds, float)
-- ARGV[4] = challenge_id (sorted-set member)
-- ARGV[5] = state
-- ARGV[6] = ttl_seconds (hash TTL)
-- ARGV[7..] = field/value pairs for HSET
local current = redis.call('HGET', KEYS[1], 'version')
local expected = tonumber(ARGV[1])

if expected == 0 then
  if current then return 0 end
else
  if not current or tonumber(current) ~= expected then return 0 end
end

redis.call('DEL', KEYS[1])
local fields = {}
for i = 7, #ARGV do fields[#fields + 1] = ARGV[i] end
redis.call('HSET', KEYS[1], unpack(fields))

if ARGV[5] == 'issued' then
  redis.call('ZADD', KEYS[2], ARGV[3], ARGV[4])
else
  redis.call('ZREM', KEYS[2], ARGV[4])
end

redis.call('EXPIRE', KEYS[1], ARGV[6])
return tonumber(ARGV[2])
"""


# One round trip: read, decide, write.
#
#   KEYS[1] = challenge:{id}   (hash)
#   KEYS[2] = challenge:expiry (sorted set)
#
#   ARGV[1] = action
#   ARGV[2] = now (epoch seconds, float)
#   ARGV[3] = solution sha256 hex (computed by the caller; Lua never hashes)
#   ARGV[4] = burn TTL seconds (post-transition TTL, roughly the grace floor)
#
#   returns 0   not found, no stored hash
#   returns 1   first correct answer, state -> solved (CAS v -> v+1)
#   returns 2   wrong solution or action, state -> failed (CAS v -> v+1)
#   returns 10  already solved, no write and no version churn (retry id)
#   returns 20  stored state was already terminal (failed/expired)
#   returns 30  was issued but past expires_at, state -> expired (CAS)
#
# The compare runs against stored values inside the script itself, so
# there is no read-modify-write window spanning two network round trips
# and no command can slip in between load and commit.
SOLVE_LUA = """
local parts = redis.call('HMGET', KEYS[1],
  'id', 'state', 'action', 'solution_hash', 'version',
  'created_at', 'expires_at', 'expires_at_ts')
local id, state, action, sha, version = parts[1], parts[2], parts[3], parts[4], parts[5]
local created_at, expires_at, expires_ts = parts[6], parts[7], parts[8]

if not state then return 0 end
if state == 'solved' then return 10 end
if state ~= 'issued' then return 20 end

local function burn(new_state, new_version)
  redis.call('DEL', KEYS[1])
  redis.call('HSET', KEYS[1],
    'id', id, 'state', new_state, 'action', action, 'solution_hash', sha,
    'created_at', created_at, 'expires_at', expires_at,
    'expires_at_ts', expires_ts, 'version', tostring(new_version))
  redis.call('ZREM', KEYS[2], id)     -- terminal states leave the expiry index
  redis.call('EXPIRE', KEYS[1], ARGV[4])
end

if tonumber(expires_ts) <= tonumber(ARGV[2]) then
  burn('expired', tonumber(version) + 1)
  return 30
end

if action ~= ARGV[1] or sha ~= ARGV[3] then
  burn('failed', tonumber(version) + 1)
  return 2
end

burn('solved', tonumber(version) + 1)
return 1
"""


class RedisChallengeRepository(ChallengeRepository):
    """Redis adapter for the ChallengeRepository port.

    Writes go through CAS Lua scripts so concurrent writers can't
    corrupt the state machine, and the expiry sorted set doubles as
    the find_due_for_expiry index.
    """

    def __init__(
        self,
        redis: Redis,
        *,
        grace: timedelta = timedelta(minutes=10),
        key_prefix: str = "challenge",
    ) -> None:
        self._redis = redis
        self._grace = grace
        self._prefix = key_prefix
        self._expiry_key = f"{key_prefix}:expiry"
        self._cas = redis.register_script(CAS_SAVE_LUA)
        self._solve = redis.register_script(SOLVE_LUA)
        observability.register_script_name("challenge_cas_save", CAS_SAVE_LUA)
        observability.register_script_name("challenge_solve", SOLVE_LUA)

    # ---- keys ----
    def _key(self, cid: str | ChallengeId) -> str:
        return f"{self._prefix}:{cid}"

    # ---- ChallengeRepository ----
    async def get(self, challenge_id: ChallengeId) -> Challenge | None:
        data = await self._redis.hgetall(self._key(challenge_id))
        return self._to_domain(data) if data else None

    async def save(self, challenge: Challenge) -> None:
        expected = challenge._version
        new_version = expected + 1

        now = datetime.now(timezone.utc)
        ttl_seconds = max(
            int((challenge.expires_at + self._grace - now).total_seconds()),
            int(self._grace.total_seconds()),
            60,  # hard floor so a row can't die before the scheduler sees it
        )

        # expires_at_ts mirrors the expiry zset score as a plain number,
        # so the solve script can compare against the wall clock instead
        # of parsing ISO timestamps in Lua.
        fields = [
            "id",             str(challenge.id),
            "state",          challenge.state.value,
            "action",         challenge.proof.action.value,
            "solution_hash",  challenge.proof.solution_hash.hex(),
            "created_at",     challenge.created_at.isoformat(),
            "expires_at",     challenge.expires_at.isoformat(),
            "expires_at_ts",  str(challenge.expires_at.timestamp()),
            "version",        str(new_version),
        ]

        result = await self._cas(
            keys=[self._key(challenge.id), self._expiry_key],
            args=[
                str(expected),
                str(new_version),
                str(challenge.expires_at.timestamp()),
                str(challenge.id),
                challenge.state.value,
                str(ttl_seconds),
                *fields,
            ],
        )
        if int(result) == 0:
            observability.record_stale_challenge()   # we lost the CAS race, worth counting
            raise StaleChallenge(challenge.id)
        challenge._version = new_version

    async def attempt_solve(
        self,
        challenge_id: ChallengeId,
        action: Action,
        solution_sha256_hex: str,
        *,
        now: datetime,
    ) -> SolveOutcome:
        result = await self._solve(
            keys=[self._key(challenge_id), self._expiry_key],
            args=[
                action.value,                       # ARGV[1]
                str(now.timestamp()),               # ARGV[2]
                solution_sha256_hex,                # ARGV[3]
                str(int(self._grace.total_seconds())),   # ARGV[4] burn TTL
            ],
        )
        code = int(result)
        if code == 1:
            return SolveOutcome.SOLVED
        if code == 2:
            return SolveOutcome.WRONG
        if code == 10:
            return SolveOutcome.ALREADY_SOLVED
        if code == 20:
            return SolveOutcome.NOT_SOLVABLE
        if code == 30:
            return SolveOutcome.EXPIRED
        if code == 0:
            return SolveOutcome.NOT_FOUND
        raise DomainError(f"unexpected solve result {code}")

    async def find_due_for_expiry(
        self,
        now: datetime,
        limit: int = 100,
    ) -> Sequence[Challenge]:
        ids = await self._redis.zrangebyscore(
            self._expiry_key, "-inf", now.timestamp(), start=0, num=limit,
        )
        if not ids:
            return []

        pipe = self._redis.pipeline()
        for cid in ids:
            pipe.hgetall(self._key(cid))
        results = await pipe.execute()

        challenges: list[Challenge] = []
        orphans: list[str] = []
        for cid, data in zip(ids, results):
            if not data or data.get("state") != "issued":
                orphans.append(cid)   # hash expired or state is terminal, drop from index
                continue
            challenges.append(self._to_domain(data))

        if orphans:
            await self._redis.zrem(self._expiry_key, *orphans)

        return challenges

    # ---- mapping ----
    def _to_domain(self, data: dict[str, str]) -> Challenge:
        return Challenge(
            id=ChallengeId.from_str(data["id"]),
            _state=State.from_str(data["state"]),
            _proof=Proof(
                action=Action.from_str(data["action"]),
                solution_hash=bytes.fromhex(data["solution_hash"]),
            ),
            _created_at=datetime.fromisoformat(data["created_at"]),
            _expires_at=datetime.fromisoformat(data["expires_at"]),
            _version=int(data["version"]),
        )