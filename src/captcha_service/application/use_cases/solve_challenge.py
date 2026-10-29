from datetime import timedelta
import hashlib

from captcha_service.application.dtos.captcha import SolveChallengeCommand, SolveChallengeResult
from captcha_service.application.exceptions import ChallengeNotFound, InvalidSolution
from captcha_service.application.ports.clock import Clock
from captcha_service.application.ports.metrics import UsageMetrics
from captcha_service.application.ports.token import TokenClaims, TokenIssuer
from captcha_service.domain.ports.challenge_repository import ChallengeRepository
from captcha_service.domain.value_objects.action import Action
from captcha_service.domain.exceptions import InvalidChallengeState
from captcha_service.domain.value_objects.challenge_id import ChallengeId
from captcha_service.domain.value_objects.solve_outcome import SolveOutcome



def _solution_sha(solution: str) -> str:
    """Digest of the submitted answer; stores never see plaintext solutions."""
    return hashlib.sha256(solution.encode("utf-8")).hexdigest()


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

        # The store judges the answer in a single atomic operation, so
        # two concurrent solvers can't both win and honest callers
        # never see a version race.
        outcome = await self._repo.attempt_solve(
            cid, action, _solution_sha(cmd.solution), now=now,
        )

        if outcome is SolveOutcome.NOT_FOUND:
            raise ChallengeNotFound(cid)
        if outcome in (SolveOutcome.EXPIRED, SolveOutcome.NOT_SOLVABLE):
            raise InvalidChallengeState(
                f"challenge {cid} is {outcome.value}; cannot be solved"
            )
        if outcome is SolveOutcome.WRONG:
            self._metrics.record_solve(False)
            raise InvalidSolution(cid)                     # challenge is spent, ask for a new one

        # Both SOLVED and ALREADY_SOLVED authorize a token. The retry
        # path writes nothing: a caller that won a token but dropped the
        # response can solve again and re-mint without touching storage.

        claims = TokenClaims(
            challenge_id=cid,
            action=action,
            issued_at=now,
            expires_at=now + self._token_ttl,
        )
        return SolveChallengeResult(
            token=self._tokens.issue(claims),
            expires_at=claims.expires_at,
        )