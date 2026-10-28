from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

from captcha_service.application.ports.clock import Clock
from captcha_service.domain.exceptions import StaleChallenge
from captcha_service.domain.ports.challenge_repository import ChallengeRepository
from captcha_service.infrastructure import observability

log = logging.getLogger(__name__)


class ExpirySweeper:
    """Background loop that flips overdue ISSUED challenges to expired.

    Without this, expired challenges only leave Redis via their TTL
    (expires_at + grace) and the challenge:expiry sorted set never
    shrinks on its own — it is only cleaned as a side effect of
    find_due_for_expiry. Sweeping gives us real expiry bookkeeping:
    state transitions actually happen, terminal rows drop out of the
    index immediately by way of the normal CAS save, and orphans get
    removed.

    Redis failures are logged and counted, then the loop simply tries
    again next tick — a transient outage must not kill the sweeper.
    """

    def __init__(
        self,
        repo: ChallengeRepository,
        clock: Clock,
        interval: timedelta,
        batch_limit: int = 500,
    ) -> None:
        self._repo = repo
        self._clock = clock
        self._interval = interval
        self._batch_limit = batch_limit

    async def sweep_once(self) -> int:
        """Expire every due challenge in one bounded batch. Returns count."""
        now = self._clock.now()
        due = await self._repo.find_due_for_expiry(now, limit=self._batch_limit)
        expired = 0
        for challenge in due:
            try:
                challenge.expire(now=now)
                await self._repo.save(challenge)
                expired += 1
            except StaleChallenge:
                # Another writer (solver/redeemer) moved it first; it was
                # not issuable anyway. Nothing to do.
                continue
        observability.expiries_swept(expired)
        return expired

    async def run_forever(self) -> None:
        log.info("expiry sweeper starting", extra={"ctx": {
            "interval_s": self._interval.total_seconds(),
            "batch_limit": self._batch_limit,
        }})
        while True:
            await asyncio.sleep(self._interval.total_seconds())
            try:
                await self.sweep_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("expiry sweep failed; retrying next interval")
