from abc import ABC, abstractmethod

from captcha_service.domain.value_objects.challenge_id import ChallengeId


class ChallengeImageStore(ABC):
    """Byte storage for a rendered challenge image, keyed by challenge id.

    An image never changes for the life of its challenge, so it is
    write-once, read-only. Keep it out of the Challenge aggregate:
    solutions are loaded with HGETALL, and dragging a PNG along there
    would be a waste.
    """

    @abstractmethod
    async def save(self, challenge_id: ChallengeId, png: bytes, ttl_seconds: int) -> None:
        """Save the rendered image; it should expire with the challenge."""
        ...

    @abstractmethod
    async def load(self, challenge_id: ChallengeId) -> bytes | None:
        """The stored bytes, or None once the image is gone."""
        ...
