import hashlib
import hmac
from dataclasses import dataclass

from captcha_service.domain.exceptions import InvalidProof
from captcha_service.domain.value_objects.action import Action


_SHA256_LEN = 32  # bytes


@dataclass(frozen=True, slots=True)
class Proof:
    """The committed solution for a challenge, bound to one action."""

    action: Action
    solution_hash: bytes         

    def __post_init__(self) -> None:
        if not isinstance(self.action, Action):
            raise InvalidProof(
                f"Proof expects Action, got {type(self.action).__name__}"
            )
        if not isinstance(self.solution_hash, bytes):
            raise InvalidProof(
                f"Proof expects bytes for solution_hash, "
                f"got {type(self.solution_hash).__name__}"
            )
        if len(self.solution_hash) != _SHA256_LEN:
            raise InvalidProof(
                f"solution_hash must be {_SHA256_LEN} bytes, "
                f"got {len(self.solution_hash)}"
            )

    @classmethod
    def from_solution(cls, *, action: Action, solution: str) -> "Proof":
        if not isinstance(solution, str) or not solution:
            raise InvalidProof("solution must be a non-empty string")
        digest = hashlib.sha256(solution.encode("utf-8")).digest()
        return cls(action=action, solution_hash=digest)

    def matches(self, *, action: Action, solution: str) -> bool:
        """True iff both action and solution match the commitment."""
        if self.action != action:
            return False
        candidate = hashlib.sha256(solution.encode("utf-8")).digest()
        return hmac.compare_digest(self.solution_hash, candidate)