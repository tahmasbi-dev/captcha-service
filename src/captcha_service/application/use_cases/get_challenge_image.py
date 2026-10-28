from captcha_service.application.exceptions import ChallengeNotFound
from captcha_service.application.ports.challenge_images import ChallengeImageStore
from captcha_service.domain.value_objects.challenge_id import ChallengeId


class GetChallengeImage:
    """Serve the stored PNG for a challenge, straight from the image store."""

    def __init__(self, images: ChallengeImageStore) -> None:
        self._images = images

    async def execute(self, challenge_id: str) -> bytes:
        cid = ChallengeId.from_str(challenge_id)   # 400 on malformed uuid
        payload = await self._images.load(cid)
        if payload is None:
            raise ChallengeNotFound(cid)           # never issued / TTL'd out
        return payload
