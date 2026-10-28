from captcha_service.application.dtos.captcha import VerifyTokenCommand, VerifyTokenResult
from captcha_service.application.exceptions import ChallengeNotFound, InvalidToken
from captcha_service.application.ports.token import TokenVerifier
from captcha_service.domain.ports.proof_ledger import ProofLedger
from captcha_service.domain.value_objects.redemption import RedemptionOutcome


class VerifyToken:
    """Verify a solve token and redeem the challenge behind it.

    Verification is no longer purely stateless: a valid token authorizes
    exactly one successful verdict. The first caller consumes the
    challenge atomically (see ProofLedger); a retry within the retention
    window replays the recorded verdict instead of failing.
    """

    def __init__(self, verifier: TokenVerifier, ledger: ProofLedger) -> None:
        self._verifier = verifier
        self._ledger = ledger

    async def execute(self, cmd: VerifyTokenCommand) -> VerifyTokenResult:
        claims = self._verifier.verify(cmd.token)          # InvalidToken / ExpiredToken

        # Bindings: the token must have been issued for THIS challenge and THIS action.
        if str(claims.challenge_id) != cmd.challenge_id:
            raise InvalidToken("token bound to a different challenge")

        if claims.action.value != cmd.action:
            raise InvalidToken("token bound to a different action")

        # Single use + network-retry safety, in one atomic Redis operation:
        # the first verification consumes the challenge; the SAME token may
        # replay the recorded verdict exactly once; any other token is burned.
        outcome = await self._ledger.redeem(
            claims.challenge_id, claims.action, cmd.token
        )
        if outcome is RedemptionOutcome.NOT_FOUND:
            raise ChallengeNotFound(claims.challenge_id)   # consumed AND retention gone: dead end
        if outcome is RedemptionOutcome.CONFLICT:
            raise InvalidToken("token already redeemed for this challenge")

        return VerifyTokenResult(
            valid=True,
            challenge_id=str(claims.challenge_id),
            action=claims.action.value,
        )