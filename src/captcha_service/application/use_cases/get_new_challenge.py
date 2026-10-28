import asyncio
from datetime import timedelta

from captcha_service.application.dtos.captcha import NewChallengeCommand, NewChallengeResult
from captcha_service.application.ports.captcha_generator import CaptchaGenerator
from captcha_service.application.ports.challenge_images import ChallengeImageStore
from captcha_service.application.ports.clock import Clock
from captcha_service.domain.entities.challenge import Challenge
from captcha_service.domain.ports.challenge_repository import ChallengeRepository
from captcha_service.domain.value_objects.action import Action


class GetNewChallenge:
    def __init__(
        self,
        repo: ChallengeRepository,
        captcha: CaptchaGenerator,
        clock: Clock,
        ttl: timedelta,
        images: ChallengeImageStore,
        image_ttl: timedelta,
    ) -> None:
        self._repo = repo
        self._captcha = captcha
        self._clock = clock
        self._ttl = ttl
        self._images = images
        self._image_ttl = image_ttl

    async def execute(self, cmd: NewChallengeCommand) -> NewChallengeResult:
        action = Action.from_str(cmd.action)               # 400 on bad action

        # Pillow rendering is CPU-bound: keep it off the event loop so a
        # burst of issuances can't stall every other request.
        solution = await asyncio.to_thread(self._captcha.generate)
        challenge = Challenge.issue(
            action=action,
            solution=solution,
            now=self._clock.now(),
            ttl=self._ttl,
        )
        await self._repo.save(challenge)

        # Persist the rendered image so GET /challenges/{id}/image can
        # serve raw PNG without any re-render; dies with the challenge TTL.
        payload = await asyncio.to_thread(self._captcha.render, solution)
        await self._images.save(challenge.id, payload, int(self._image_ttl.total_seconds()))

        return NewChallengeResult(
            challenge_id=str(challenge.id),
            payload=payload,
            expires_at=challenge.expires_at,
        )