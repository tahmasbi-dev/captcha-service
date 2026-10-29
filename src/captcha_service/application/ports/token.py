from dataclasses import dataclass
from datetime import datetime
from abc import ABC, abstractmethod


from captcha_service.domain.value_objects.challenge_id import ChallengeId
from captcha_service.domain.value_objects.action import Action


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """The facts a JWT carries after verification; mirrors the domain bindings."""
    challenge_id: ChallengeId
    action: Action
    issued_at: datetime
    expires_at: datetime


class TokenIssuer(ABC):
    @abstractmethod
    def issue(self, claims: TokenClaims) -> str:
        """Sign the claims into a compact JWT. Raises if serialization fails."""
        ...


class TokenVerifier(ABC):
    @abstractmethod
    def verify(self, token: str) -> TokenClaims:
        """Validate signature, exp and iss, then return the claims.

        ``InvalidToken`` for malformed tokens, bad signatures or a
        wrong issuer; ``ExpiredToken`` when the signature checks out
        but `exp` has passed.
        """
        ...