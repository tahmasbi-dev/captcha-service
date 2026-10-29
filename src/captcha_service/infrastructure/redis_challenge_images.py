from __future__ import annotations

import base64

from redis.asyncio import Redis

from captcha_service.application.ports.challenge_images import ChallengeImageStore
from captcha_service.domain.value_objects.challenge_id import ChallengeId


class RedisChallengeImageStore(ChallengeImageStore):
    """Rendered PNGs live in their own keys, TTL'd alongside the challenge.

    Not inside the challenge hash on purpose: the solve path reads the
    hash with HGETALL and shouldn't carry ~10 KB of image bytes it
    will never use. These keys expire on their own, so redeeming or
    failing a challenge needs no explicit cleanup here.

    The payload is base64 rather than raw bytes because the shared
    Redis client decodes as text, and raw image bytes would get
    mangled by utf-8 decoding. Base64 round-trips lossless; the 25%
    overhead lives off the hot path.
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
