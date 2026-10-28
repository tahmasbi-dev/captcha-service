from __future__ import annotations

import base64

from redis.asyncio import Redis

from captcha_service.application.ports.challenge_images import ChallengeImageStore
from captcha_service.domain.value_objects.challenge_id import ChallengeId


class RedisChallengeImageStore(ChallengeImageStore):
    """Rendered PNGs live in their own keys, TTL'd alongside the challenge.

    Deliberately NOT inside the challenge hash: the solve path reads the
    hash with HGETALL and must not pay for ~10 KB of image bytes it
    never uses. These keys die on their own TTL, so redemption needs no
    extra deletion, and burning/failed states don't touch them either.

    The bytes go in base64-encoded because the shared Redis client
    decodes responses as text (utf-8 with replacement) — raw payload
    bytes would not survive a round trip through TEXT decoding, while
    base64 is guaranteed lossless. The 25% overhead is off the hot path.
    """

    def __init__(self, redis: Redis, *, key_prefix: str = "challenge:image") -> None:
        self._redis = redis
        self._prefix = key_prefix

    def _key(self, challenge_id: ChallengeId) -> str:
        return f"{self._prefix}:{challenge_id}"

    async def save(self, challenge_id: ChallengeId, png: bytes, ttl_seconds: int) -> None:
        encoded = base64.b64encode(png)
        await self._redis.set(self._key(challenge_id), encoded, ex=max(int(ttl_seconds), 60))

    async def load(self, challenge_id: ChallengeId) -> bytes | None:
        encoded = await self._redis.get(self._key(challenge_id))
        if encoded is None:
            return None
        return base64.b64decode(encoded if isinstance(encoded, bytes) else encoded.encode("ascii"))
