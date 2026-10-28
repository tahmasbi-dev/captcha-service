from abc import ABC, abstractmethod

from captcha_service.domain.value_objects.action import Action
from captcha_service.domain.value_objects.challenge_id import ChallengeId
from captcha_service.domain.value_objects.redemption import RedemptionOutcome


class ProofLedger(ABC):
    """Single-use redemption of a solved challenge's proof.

    One call must be one atomic storage operation (no interleaving with
    any other redeem or challenge save):

    1. **First verification (NEW).** The challenge must exist in the
       SOLVED state. The aggregate is consumed — removed from storage
       together with the token-use authorization it granted — and the
       verdict is recorded briefly, bound to the exact token presented.

    2. **Network-retry safety (REPLAY, exactly once).** If the resource
       server sent a valid token but lost the connection before reading
       the response, its retry — the SAME token — finds the record and
       gets the same verdict again. The replay itself consumes the
       record: a second retry after that, and any retry after token
       expiry, are definitive misses.

    3. **No second life for one solve (CONFLICT).** A different token
       (e.g. one re-minted by an idempotent solve retry) presented after
       the proof was consumed is rejected. Token, challenge and action
       are bound together: one solve buys at most one verdict plus one
       same-token network retry, never two passes.

    4. **Nothing to redeem (NOT_FOUND).** No record and no solved
       challenge: the token may still verify cryptographically, but its
       proof cannot be shown solved, so the caller gets a miss.

    Retries must arrive while the token is still valid; the retention
    window is therefore shorter than the token TTL.
    """

    @abstractmethod
    async def redeem(
        self,
        challenge_id: ChallengeId,
        action: Action,
        token: str,
    ) -> RedemptionOutcome:
        """Atomically consume-or-replay the verdict for this challenge."""
        ...
