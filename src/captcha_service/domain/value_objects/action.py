import re
from dataclasses import dataclass
from captcha_service.domain.exceptions import InvalidAction


_ACTION_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


@dataclass(frozen=True, slots=True)
class Action:
    """The action a challenge protects: 'login', 'register', 'password_reset', ..."""

    _value: str

    def __post_init__(self) -> None:
        if not isinstance(self._value, str):
            raise InvalidAction(
                f"Action expects str, got {type(self._value).__name__}"
            )
        if not _ACTION_RE.match(self._value):
            raise InvalidAction(f"invalid action {self._value!r}")

    @classmethod
    def from_str(cls, raw: str) -> "Action":
        return cls(raw)

    @property
    def value(self) -> str:
        return self._value

    def __str__(self) -> str:
        return self._value