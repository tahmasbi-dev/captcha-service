from __future__ import annotations
from abc import ABC, abstractmethod

from datetime import datetime
from typing import Sequence
from captcha_service.domain.entities.challenge import Challenge
from captcha_service.domain.value_objects.action import Action
from captcha_service.domain.value_objects.challenge_id import ChallengeId
from captcha_service.domain.value_objects.solve_outcome import SolveOutcome


class ChallengeRepository(ABC):
    """Port for persisting and loading the Challenge aggregate.

    The only adapter is Redis. Implementations must guarantee:

    1. **Atomic save with optimistic concurrency control.**
       Two callers who loaded the same version cannot both succeed;
       the loser raises ``StaleChallenge``.

    2. **A time-ordered secondary index on ``expires_at``.**
       ``find_due_for_expiry`` must be O(log N + limit), not a scan.

    3. **A grace window after ``expires_at``.**
       The row is not removed from Redis until some grace period has
       passed, so the scheduler can still observe and expire it. TTL
       is the adapter's concern; the port only states the invariant.

    4. **Rehydration preserves the version.**
       ``get`` → mutate → ``save`` must round-trip the version so the
       CAS check is meaningful.
    """
    
    @abstractmethod
    async def get(self, challenge_id: ChallengeId) -> Challenge | None:
        """Load by id.

        Returns ``None`` if the challenge is absent, past its grace
        window, or was never created. Absence is not an error here;
        the application layer decides whether to raise
        ``ChallengeNotFound``.
        """
        ...
        
    @abstractmethod
    async def save(self, challenge: Challenge) -> None:
        """Persist the aggregate.

        On success, the aggregate's version is advanced in place.

        Raises:
            StaleChallenge: the aggregate was modified concurrently
                (version mismatch) or deleted between load and save.
        """
        ...
        
    @abstractmethod
    async def find_due_for_expiry(
        self,
        now: datetime,
        limit: int = 100,
    ) -> Sequence[Challenge]:
        """Challenges still ISSUED whose ``expires_at <= now``.

        Ordered by ``expires_at`` ascending (oldest first) so the
        scheduler processes the longest-overdue challenges first.

        ``limit`` is mandatory-by-default to keep scheduler batches
        bounded; callers loop until an empty result.
        """
        ...

    @abstractmethod
    async def attempt_solve(
        self,
        challenge_id: ChallengeId,
        action: Action,
        solution_sha256_hex: str,
        *,
        now: datetime,
    ) -> SolveOutcome:
        """Judge one submitted solution in a single atomic store operation.

        The whole load-compare-decide-write sequence must happen with no
        other command interleaved, so two concurrent solvers of the same
        challenge cannot both "win" and no honest caller ever sees a
        version race from a read that went stale mid-request.

        Exactly one of:

        * ``SOLVED`` — first correct answer; the state moved to solved.
        * ``ALREADY_SOLVED`` — the challenge was already solved; report
          success again WITHOUT touching storage (no version churn, so
          idempotent token re-mints cost nothing).
        * ``WRONG`` — bad solution or wrong action; burned to failed.
        * ``EXPIRED`` — was still issued past ``expires_at``; expired in place.
        * ``NOT_SOLVABLE`` — stored state already terminal.
        * ``NOT_FOUND`` — absent (never existed, TTL'd out, or consumed
          by redemption).

        ``solution_sha256_hex`` is the digest of the submitted answer,
        computed by the caller; implementations compare digests, never
        plaintext solutions.
        """
        ...