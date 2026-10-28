from datetime import timedelta

from captcha_service.application.dtos.captcha import NewChallengeCommand, NewChallengeResult
from captcha_service.application.ports.captcha_generator import CaptchaGenerator
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
    ) -> None:
        self._repo = repo
        self._captcha = captcha
        self._clock = clock
        self._ttl = ttl

    async def execute(self, cmd: NewChallengeCommand) -> NewChallengeResult:
        action = Action.from_str(cmd.action)               # 400 on bad action
        solution = self._captcha.generate()                # app-layer concern
        challenge = Challenge.issue(
            action=action,
            solution=solution,
            now=self._clock.now(),
            ttl=self._ttl,
        )
        await self._repo.save(challenge)
        return NewChallengeResult(
            challenge_id=str(challenge.id),
            payload=self._captcha.render(solution),
            expires_at=challenge.expires_at,
        )