from abc import ABC, abstractmethod

from captcha_service.domain.value_objects.challenge_id import ChallengeId


class ChallengeImageStore(ABC):
    """Byte storage for a rendered challenge image, keyed by challenge id.

    Images are immutable for the life of a challenge, so storage is
    write-once/read-only. Implementations must not keep the image inside
    the Challenge aggregate — solutions are looked up via HGETALL and
    would drag megabytes of PNG along for the ride.
    """

    @abstractmethod
    async def save(self, challenge_id: ChallengeId, png: bytes, ttl_seconds: int) -> None:
        """Persist the rendered image, expiring it with the challenge."""
        ...

    @abstractmethod
    async def load(self, challenge_id: ChallengeId) -> bytes | None:
        """The stored bytes, or None once absent/expired."""
        ...
