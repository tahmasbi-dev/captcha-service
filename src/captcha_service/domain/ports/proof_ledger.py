from abc import ABC, abstractmethod

from captcha_service.domain.value_objects.action import Action
from captcha_service.domain.value_objects.challenge_id import ChallengeId
from captcha_service.domain.value_objects.redemption import RedemptionOutcome


class ProofLedger(ABC):
    """Single-use redemption of a solved challenge's proof.

    One call is one atomic storage operation; nothing may interleave
    with another redeem or a challenge save.

    1. First verification (NEW). The challenge must exist in the SOLVED
       state. It is consumed: removed from storage along with the
       token-use authorization it granted, and the verdict is recorded
       for a short while, bound to the exact token presented.

    2. Network-retry safety (REPLAY, exactly once). A resource server
       that sent a valid token but lost the connection before reading
       the response can retry with the same token and find the record
       there, getting the same verdict again. The replay itself
       consumes the record, so a second retry and any retry after the
       token expires are hard misses.

    3. No second life for one solve (CONFLICT). A different token (say,
       one re-minted by an idempotent solve retry) presented after the
       proof was consumed is rejected. Token, challenge and action are
       bound together: one solve buys at most one verdict plus one
       same-token retry, never two passes.

    4. Nothing to redeem (NOT_FOUND). No record and no solved
       challenge. The token may still verify cryptographically, but
       the proof behind it can't be shown solved, so the caller gets
       a miss.

    Retries only work while the token is still valid, so the retention
    window has to be shorter than the token TTL.
    """

    @abstractmethod
    async def redeem(
        self,
        challenge_id: ChallengeId,
        action: Action,
        token: str,
    ) -> RedemptionOutcome:
        """Atomically consume the verdict for this challenge, or replay
        it once more if this exact token already earned it."""
        ...
