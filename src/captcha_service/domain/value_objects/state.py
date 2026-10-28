from dataclasses import dataclass
from enum import StrEnum

from captcha_service.domain.exceptions import InvalidChallengeState


class _StateKind(StrEnum):
    ISSUED  = "issued"
    EXPIRED = "expired"
    SOLVED  = "solved"
    FAILED  = "failed"


_TERMINAL = frozenset({_StateKind.EXPIRED, _StateKind.SOLVED, _StateKind.FAILED})

_TRANSITIONS: dict[_StateKind, frozenset[_StateKind]] = {
    _StateKind.ISSUED:  frozenset({_StateKind.SOLVED, _StateKind.EXPIRED, _StateKind.FAILED}),
    _StateKind.SOLVED:  frozenset(),
    _StateKind.EXPIRED: frozenset(),
    _StateKind.FAILED:  frozenset(),
}


@dataclass(frozen=True, slots=True)
class State:
    """Immutable Value Object for a challenge's lifecycle state."""

    _kind: _StateKind

    def __post_init__(self) -> None:
        if not isinstance(self._kind, _StateKind):
            raise InvalidChallengeState(
                f"State expects _StateKind, got {type(self._kind).__name__}"
            )

    @classmethod
    def issued(cls) -> "State":  return cls(_StateKind.ISSUED)
    @classmethod
    def solved(cls) -> "State":  return cls(_StateKind.SOLVED)
    @classmethod
    def expired(cls) -> "State": return cls(_StateKind.EXPIRED)
    @classmethod
    def failed(cls) -> "State":  return cls(_StateKind.FAILED)

    @classmethod
    def from_str(cls, raw: str) -> "State":
        try:
            return cls(_StateKind(raw))
        except ValueError as exc:
            raise InvalidChallengeState(f"unknown state {raw!r}") from exc

    @property
    def value(self) -> str:
        return self._kind.value

    @property
    def is_issued(self) -> bool:  return self._kind is _StateKind.ISSUED
    @property
    def is_solved(self) -> bool:  return self._kind is _StateKind.SOLVED
    @property
    def is_expired(self) -> bool: return self._kind is _StateKind.EXPIRED
    @property
    def is_failed(self) -> bool:  return self._kind is _StateKind.FAILED
    @property
    def can_be_solved(self) -> bool:
        return self.can_transition_to(State.solved())
    
    @property
    def is_terminal(self) -> bool:
        return self._kind in _TERMINAL

    def can_transition_to(self, target: "State") -> bool:
        return target._kind in _TRANSITIONS[self._kind]

    def _transition_to(self, target: "State") -> "State":
        if not self.can_transition_to(target):
            raise InvalidChallengeState(
                f"cannot transition from {self.value!r} to {target.value!r}"
            )
        return target

    def solve(self) -> "State":  return self._transition_to(State.solved())
    def expire(self) -> "State": return self._transition_to(State.expired())
    def fail(self) -> "State":   return self._transition_to(State.failed())

    def __str__(self) -> str:
        return self._kind.value