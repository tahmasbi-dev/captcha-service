from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import jwt

from captcha_service.application.exceptions import ExpiredToken, InvalidToken
from captcha_service.application.ports.token import TokenClaims
from captcha_service.domain.value_objects.action import Action
from captcha_service.domain.value_objects.challenge_id import ChallengeId


class JwtTokenService:
    """Signs and verifies solve tokens.

    Two modes, chosen by settings:

    * HS* - symmetric: the same secret encodes and decodes. Everyone who
      can verify can also mint. Fine while only this service holds the
      key.
    * RS256 / EdDSA - asymmetric: tokens are signed with the private key
      and verified with the public key. A remote resource server that
      only verifies holds the public key, so a compromise of that server
      cannot mint tokens - it can at most present ones it legitimately
      received.

    Either way, ``verify`` pins the algorithm to the configured one (a
    list, never a merge) and requires iss/sub/act/iat/exp, which closes
    the classic ``alg: none`` / alg-confusion holes.
    """

    def __init__(
        self,
        *,
        issuer: str,
        algorithm: str = "HS256",
        secret: Optional[bytes] = None,
        private_key_pem: Optional[str] = None,
        public_key_pem: Optional[str] = None,
    ) -> None:
        if algorithm.startswith("HS"):
            if secret is None:
                raise ValueError("HS* algorithms require `secret`")
            self._signing_key: object = secret
            self._verifying_key: object = secret
        else:
            if private_key_pem is None or public_key_pem is None:
                raise ValueError(
                    f"{algorithm} requires both `private_key_pem` and `public_key_pem`"
                )
            self._signing_key = private_key_pem
            self._verifying_key = public_key_pem
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
        return jwt.encode(payload, self._signing_key, algorithm=self._algorithm)

    # ---- TokenVerifier ----
    def verify(self, token: str) -> TokenClaims:
        try:
            payload = jwt.decode(
                token,
                self._verifying_key,
                algorithms=[self._algorithm],      # list, never a string: keeps alg confusion closed
                issuer=self._issuer,
                options={"require": ["iss", "sub", "act", "iat", "exp"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise ExpiredToken("token expired") from exc
        except jwt.InvalidTokenError as exc:
            # bad signature, wrong issuer, missing claim, junk base64, all of it
            raise InvalidToken(str(exc)) from exc

        try:
            return TokenClaims(
                challenge_id=ChallengeId.from_str(payload["sub"]),
                action=Action.from_str(payload["act"]),
                issued_at=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
                expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
            )
        except (ValueError, TypeError) as exc:
            # signature checked out, but the payload is junk to us
            raise InvalidToken(f"malformed claims: {exc}") from exc
