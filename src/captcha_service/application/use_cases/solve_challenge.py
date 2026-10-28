from datetime import timedelta

from captcha_service.application.dtos.captcha import SolveChallengeCommand, SolveChallengeResult
from captcha_service.application.exceptions import ChallengeNotFound, InvalidSolution
from captcha_service.application.ports.clock import Clock
from captcha_service.application.ports.metrics import UsageMetrics
from captcha_service.application.ports.token import TokenClaims, TokenIssuer
from captcha_service.domain.ports.challenge_repository import ChallengeRepository
from captcha_service.domain.value_objects.action import Action
from captcha_service.domain.value_objects.challenge_id import ChallengeId


class SolveChallenge:
    def __init__(
        self,
        repo: ChallengeRepository,
        tokens: TokenIssuer,
        clock: Clock,
        token_ttl: timedelta,
        metrics: UsageMetrics,
    ) -> None:
        self._repo = repo
        self._tokens = tokens
        self._clock = clock
        self._token_ttl = token_ttl
        self._metrics = metrics

    async def execute(self, cmd: SolveChallengeCommand) -> SolveChallengeResult:
        cid = ChallengeId.from_str(cmd.challenge_id)       # 400 on malformed uuid
        action = Action.from_str(cmd.action)
        now = self._clock.now()

        challenge = await self._repo.get(cid)
        if challenge is None:
            raise ChallengeNotFound(cid)

        # Domain enforces: sync_state → can_be_solved → matches → solve()/fail()
        # Raises InvalidChallengeState if expired or already terminal.
        challenge.accept_solution(action=action, solution=cmd.solution, now=now)

        # Persist the resulting state (SOLVED or FAILED) before issuing anything.
        # StaleChallenge here means a concurrent solve — bubble up → 409.
        await self._repo.save(challenge)

        self._metrics.record_solve(challenge.state.is_solved)
        if not challenge.state.is_solved:
            raise InvalidSolution(cid)                     # wrong answer, burned

        claims = TokenClaims(
            challenge_id=challenge.id,
            action=action,
            issued_at=now,
            expires_at=now + self._token_ttl,
        )
        return SolveChallengeResult(
            token=self._tokens.issue(claims),
            expires_at=claims.expires_at,
        )