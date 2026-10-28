from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Sequence

from redis.asyncio import Redis

from captcha_service.domain.entities.challenge import Challenge
from captcha_service.domain.ports.challenge_repository import ChallengeRepository
from captcha_service.domain.exceptions import StaleChallenge
from captcha_service.domain.value_objects.action import Action
from captcha_service.domain.value_objects.challenge_id import ChallengeId
from captcha_service.domain.value_objects.proof import Proof
from captcha_service.domain.value_objects.state import State


_CAS_SAVE = """
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


class RedisChallengeRepository(ChallengeRepository):
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
        self._cas = redis.register_script(_CAS_SAVE)

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
            60,  # hard floor: never let a row die before the scheduler can see it
        )

        fields = [
            "id",             str(challenge.id),
            "state",          challenge.state.value,
            "action",         challenge.proof.action.value,
            "solution_hash",  challenge.proof.solution_hash.hex(),
            "created_at",     challenge.created_at.isoformat(),
            "expires_at",     challenge.expires_at.isoformat(),
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
            raise StaleChallenge(challenge.id)
        challenge._version = new_version

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
                orphans.append(cid)   # TTL'd hash or terminal state → drop from index
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