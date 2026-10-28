from __future__ import annotations
from dataclasses import dataclass
from uuid import UUID, uuid4

from captcha_service.domain.exceptions import InvalidChallengeId


@dataclass(frozen=True, slots=True, order=True)
class ChallengeId:
    """Strongly-typed identifier for the Challenge aggregate."""

    _value: UUID

    def __post_init__(self) -> None:
        if not isinstance(self._value, UUID):
            raise InvalidChallengeId(
                f"ChallengeId expects UUID, got {type(self._value).__name__}"
            )

    @classmethod
    def new(cls) -> ChallengeId:
        """Generate a fresh, unique identifier. Domain-side, not DB-side."""
        return cls(uuid4())

    @classmethod
    def from_str(cls, raw: str) -> ChallengeId:
        try:
            return cls(UUID(raw))
        except (ValueError, AttributeError, TypeError) as exc:
            raise InvalidChallengeId(f"invalid challenge id {raw!r}") from exc

    @property
    def value(self) -> UUID:
        return self._value

    def __str__(self) -> str:
        return str(self._value)