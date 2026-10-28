from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from redis.asyncio import Redis

from captcha_service.domain.exceptions import DomainError
from captcha_service.domain.ports.proof_ledger import ProofLedger
from captcha_service.domain.value_objects.action import Action
from captcha_service.domain.value_objects.challenge_id import ChallengeId
from captcha_service.domain.value_objects.redemption import RedemptionOutcome

from captcha_service.infrastructure import observability


# Single-use redemption, one atomic operation:
#
#   KEYS[1] = challenge:{id}   (hash)   — owned by RedisChallengeRepository
#   KEYS[2] = challenge:expiry (zset)   — owned by RedisChallengeRepository
#   KEYS[3] = redemption:{id}  (hash)   — verdict record (the "answer on file")
#
#   ARGV[1] = action
#   ARGV[2] = retention_seconds (record TTL)
#   ARGV[3] = challenge_id (expiry zset member)
#   ARGV[4] = redeemed_at (UTC ISO)
#   ARGV[5] = token_sha (sha256 hex of the presented token)
#
#   returns 0 — NOT_FOUND: no record, and the challenge is absent/not solved
#   returns 1 — NEW: consumed now; verdict recorded, bound to this token
#   returns 2 — REPLAY: same token retried; record granted once, then deleted
#   returns 3 — CONFLICT: proof already consumed by a different token
REDEEM_LUA = """
if redis.call('EXISTS', KEYS[3]) == 1 then
  if redis.call('HGET', KEYS[3], 'token_sha') == ARGV[5] then
    redis.call('DEL', KEYS[3])
    return 2
  end
  return 3
end

local state = redis.call('HGET', KEYS[1], 'state')
if not state or state ~= 'solved' then
  return 0
end

redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[2], ARGV[3])
redis.call('HSET', KEYS[3], 'result', 'valid', 'action', ARGV[1], 'token_sha', ARGV[5], 'redeemed_at', ARGV[4])
redis.call('EXPIRE', KEYS[3], ARGV[2])
return 1
"""


def _token_sha(token: str) -> str:
    # Bind the verdict record to the exact token presented: the raw token
    # is never stored, only its digest.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class RedisProofLedger(ProofLedger):
    """Redis adapter for the ProofLedger port.

    The record is the "answer kept for a short while": a resource server
    that lost its connection retries with the same token and still gets
    a success — exactly once. Afterwards the record is gone, so one
    solved challenge can never fund a second pass.
    """

    def __init__(
        self,
        redis: Redis,
        *,
        retention_seconds: int = 120,
        key_prefix: str = "redemption",
        challenge_prefix: str = "challenge",
    ) -> None:
        self._redis = redis
        self._retention = retention_seconds
        self._prefix = key_prefix
        self._challenge_prefix = challenge_prefix
        self._expiry_key = f"{challenge_prefix}:expiry"
        self._redeem = redis.register_script(REDEEM_LUA)
        observability.register_script_name("proof_ledger_redeem", REDEEM_LUA)

    # ---- ProofLedger ----
    async def redeem(
        self,
        challenge_id: ChallengeId,
        action: Action,
        token: str,
    ) -> RedemptionOutcome:
        result = await self._redeem(
            keys=[
                f"{self._challenge_prefix}:{challenge_id}",
                self._expiry_key,
                f"{self._prefix}:{challenge_id}",
            ],
            args=[
                action.value,
                str(self._retention),
                str(challenge_id),
                datetime.now(timezone.utc).isoformat(),
                _token_sha(token),
            ],
        )
        code = int(result)
        if code == 1:
            return RedemptionOutcome.NEW
        if code == 2:
            return RedemptionOutcome.REPLAY
        if code == 3:
            return RedemptionOutcome.CONFLICT
        if code == 0:
            return RedemptionOutcome.NOT_FOUND
        raise DomainError(f"unexpected redemption result {code}")
