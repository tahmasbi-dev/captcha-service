from captcha_service.application.dtos.captcha import VerifyTokenCommand, VerifyTokenResult
from captcha_service.application.exceptions import ChallengeNotFound, InvalidToken
from captcha_service.application.ports.metrics import UsageMetrics
from captcha_service.application.ports.token import TokenVerifier
from captcha_service.domain.ports.proof_ledger import ProofLedger
from captcha_service.domain.value_objects.redemption import RedemptionOutcome


class VerifyToken:
    """Verify a solve token and redeem the challenge behind it.

    Not a purely stateless check: a valid token buys exactly one
    successful verdict. The first caller consumes the challenge (see
    ProofLedger); a retry inside the retention window replays the
    recorded verdict instead of failing.
    """

    def __init__(self, verifier: TokenVerifier, ledger: ProofLedger, metrics: UsageMetrics) -> None:
        self._verifier = verifier
        self._ledger = ledger
        self._metrics = metrics

    async def execute(self, cmd: VerifyTokenCommand) -> VerifyTokenResult:
        claims = self._verifier.verify(cmd.token)          # InvalidToken / ExpiredToken

        # The token must have been issued for this challenge and this
        # action, not just any challenge.
        if str(claims.challenge_id) != cmd.challenge_id:
            raise InvalidToken("token bound to a different challenge")

        if claims.action.value != cmd.action:
            raise InvalidToken("token bound to a different action")

        # One atomic store op handles both single use and the
        # network-retry case: first verification consumes the challenge,
        # the same token may replay the recorded verdict once, and any
        # other token is rejected.
        outcome = await self._ledger.redeem(
            claims.challenge_id, claims.action, cmd.token
        )
        self._metrics.record_redeem(outcome)
        if outcome is RedemptionOutcome.NOT_FOUND:
            raise ChallengeNotFound(claims.challenge_id)   # consumed and retention is gone too
        if outcome is RedemptionOutcome.CONFLICT:
            raise InvalidToken("token already redeemed for this challenge")

        return VerifyTokenResult(
            valid=True,
            challenge_id=str(claims.challenge_id),
            action=claims.action.value,
        )