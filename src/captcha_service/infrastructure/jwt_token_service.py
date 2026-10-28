from __future__ import annotations

from datetime import datetime, timezone

import jwt

from captcha_service.application.exceptions import ExpiredToken, InvalidToken
from captcha_service.application.ports.token import TokenClaims
from captcha_service.domain.value_objects.action import Action
from captcha_service.domain.value_objects.challenge_id import ChallengeId


class JwtTokenService:
    def __init__(
        self,
        *,
        secret: bytes,
        issuer: str,
        algorithm: str = "HS256",
    ) -> None:
        self._secret = secret
        self._issuer = issuer
        self._algorithm = algorithm

    # ---- TokenIssuer ----
    def issue(self, claims: TokenClaims) -> str:
        payload = {
            "iss": self._issuer,
            "sub": str(claims.challenge_id),
            "act": claims.action.value,
            "iat": int(claims.issued_at.timestamp()),
            "exp": int(claims.expires_at.timestamp()),
        }
        return jwt.encode(payload, self._secret, algorithm=self._algorithm)

    # ---- TokenVerifier ----
    def verify(self, token: str) -> TokenClaims:
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],      # ← MUST be a list; blocks "alg: none"
                issuer=self._issuer,
                options={"require": ["iss", "sub", "act", "iat", "exp"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise ExpiredToken("token expired") from exc
        except jwt.InvalidTokenError as exc:
            # Covers: bad signature, wrong issuer, missing claim, malformed base64, alg confusion
            raise InvalidToken(str(exc)) from exc

        try:
            return TokenClaims(
                challenge_id=ChallengeId.from_str(payload["sub"]),
                action=Action.from_str(payload["act"]),
                issued_at=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
                expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
            )
        except (ValueError, TypeError) as exc:
            # The signature was valid but the payload is malformed — still a bad token.
            raise InvalidToken(f"malformed claims: {exc}") from exc