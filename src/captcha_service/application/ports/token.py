from dataclasses import dataclass
from datetime import datetime
from abc import ABC, abstractmethod


from captcha_service.domain.value_objects.challenge_id import ChallengeId
from captcha_service.domain.value_objects.action import Action


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """The verified facts a JWT carries. Mirrors the domain bindings."""
    challenge_id: ChallengeId
    action: Action
    issued_at: datetime
    expires_at: datetime


class TokenIssuer(ABC):
    @abstractmethod
    def issue(self, claims: TokenClaims) -> str:
        """Sign claims into a compact JWT. Raises on serialization failure."""
        ...


class TokenVerifier(ABC):
    @abstractmethod
    def verify(self, token: str) -> TokenClaims:
        """Validate signature, exp, iss; return the claims.

        Raises:
            InvalidToken: malformed, bad signature, wrong issuer.
            ExpiredToken: signature valid but past `exp`.
        """
        ...