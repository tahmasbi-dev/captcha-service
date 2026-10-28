from dataclasses import dataclass
from datetime import datetime, timedelta

from captcha_service.domain.exceptions import InvalidChallengeState
from captcha_service.domain.value_objects.challenge_id import ChallengeId
from captcha_service.domain.value_objects.state import State
from captcha_service.domain.value_objects.proof import Proof
from captcha_service.domain.value_objects.action import Action


@dataclass(eq=False)          
class Challenge:
    id: ChallengeId
    _state: State
    _proof: Proof
    _created_at: datetime
    _expires_at: datetime
    _version: int = 0          

    def __post_init__(self) -> None:
        if self._created_at.tzinfo is None or self._expires_at.tzinfo is None:
            raise InvalidChallengeState("timestamps must be timezone-aware")
        if self._expires_at <= self._created_at:
            raise InvalidChallengeState("expires_at must be after created_at")
        if self._version < 0:
            raise InvalidChallengeState("version must be non-negative")

    # construction
    @classmethod
    def issue(
        cls,
        *,
        action: Action,
        solution: str,
        now: datetime,
        ttl: timedelta,
    ) -> "Challenge":
        if ttl <= timedelta(0):
            raise InvalidChallengeState("ttl must be positive")
        return cls(
            id=ChallengeId.new(),
            _state=State.issued(),
            _proof=Proof.from_solution(action=action, solution=solution),
            _created_at=now,
            _expires_at=now + ttl,
        )

    # read
    @property
    def state(self) -> State:
        return self._state

    @property
    def proof(self) -> Proof:
        return self._proof

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def expires_at(self) -> datetime:
        return self._expires_at

    def should_expire(self, now: datetime) -> bool:
        return self._state.is_issued and now >= self._expires_at

    def effective_state(self, now: datetime) -> State:
        """State as of `now`, computed but not persisted. For read paths only."""
        return State.expired() if self.should_expire(now) else self._state

    # transitions
    def sync_state(self, now: datetime) -> None:
        """Reconcile `_state` with wall-clock. Idempotent; no-op if not stale."""
        if self.should_expire(now):
            self._state = self._state.expire()

    def expire(self, *, now: datetime) -> None:
        if self._state.is_expired:
            return
        if not self.should_expire(now):
            raise InvalidChallengeState(
                f"challenge {self.id} not yet expired "
                f"(expires at {self._expires_at.isoformat()})"
            )
        self._state = self._state.expire()

    def accept_solution(
        self, *, action: Action, solution: str, now: datetime
    ) -> None:
        self.sync_state(now)

        if self._state.is_solved:
            return                                   # idempotent client retry

        if not self._state.can_be_solved:
            raise InvalidChallengeState(
                f"challenge {self.id} is {self._state.value!r}; cannot be solved"
            )

        if not self._proof.matches(action=action, solution=solution):
            self._state = self._state.fail()          # terminal on wrong answer
            return

        self._state = self._state.solve()