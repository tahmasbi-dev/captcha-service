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

    Redis is the only adapter so far. Whatever implements this must:

    1. Save atomically with optimistic concurrency control. Two
       callers who loaded the same version cannot both succeed; the
       loser gets ``StaleChallenge``.

    2. Keep a time-ordered secondary index on ``expires_at`` so that
       ``find_due_for_expiry`` is O(log N + limit), not a scan.

    3. Keep the row around for a grace window after ``expires_at`` so
       the scheduler can still observe and expire it. The TTL behind
       that is the adapter's business; the port only states the
       invariant.

    4. Round-trip the version through ``get`` and ``save``; otw the
       CAS check means nothing.
    """
    
    @abstractmethod
    async def get(self, challenge_id: ChallengeId) -> Challenge | None:
        """Load by id, or return ``None`` if it's absent, past its
        grace window, or never existed.

        Absence is not an error here; the application layer decides
        whether that becomes ``ChallengeNotFound``.
        """
        ...
        
    @abstractmethod
    async def save(self, challenge: Challenge) -> None:
        """Persist the aggregate; the version is advanced in place on
        success.

        Raises ``StaleChallenge`` when the aggregate has been modified
        concurrently (version mismatch) or deleted mid-flight.
        """
        ...
        
    @abstractmethod
    async def find_due_for_expiry(
        self,
        now: datetime,
        limit: int = 100,
    ) -> Sequence[Challenge]:
        """Challenges still ISSUED with ``expires_at <= now``, oldest
        first, so the scheduler works through the most-overdue ones
        first.

        ``limit`` defaults to a bounded batch; callers loop until they
        get an empty result.
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

        The load, compare and write must all happen with no other
        command interleaved, so two concurrent solvers of the same
        challenge can't both win, and honest callers never end up
        racing a read that went stale mid-request.

        Returns exactly one of:

        * ``SOLVED``: first correct answer, state moved to solved.
        * ``ALREADY_SOLVED``: solved already; success reported again
          without touching storage, so idempotent token re-mints are free.
        * ``WRONG``: bad solution or wrong action; state is failed now.
        * ``EXPIRED``: still issued but past ``expires_at``, expired in place.
        * ``NOT_SOLVABLE``: stored state was already terminal.
        * ``NOT_FOUND``: gone (never existed, TTL'd out, or consumed
          by redemption).

        ``solution_sha256_hex`` is the digest of the submitted answer,
        computed by the caller. Implementations compare digests;
        plaintext solutions never come near them.
        """
        ...