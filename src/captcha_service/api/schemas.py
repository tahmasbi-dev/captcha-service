from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")   # reject unknown fields → 422 early


class NewChallengeRequest(_Base):
    action: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]*$",
        examples=["login"],
    )


class NewChallengeResponse(_Base):
    challenge_id: str
    image: str = Field(description="data:image/png;base64,... — render directly in <img src>")
    expires_at: datetime


class SolveChallengeRequest(_Base):
    action: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    # Server generates `captcha_length` chars; anything longer is a
    # probe. Bounded tightly so a sled of junk can't reach the Redis
    # compare path at all.
    solution: str = Field(..., min_length=1, max_length=32)


class SolveChallengeResponse(_Base):
    token: str
    expires_at: datetime


class VerifyTokenRequest(_Base):
    # All three are server-issued values, not free text: a UUID, an
    # action slug and a compact JWT. Tight bounds stop a caller with
    # the internal key (or a stolen header) from feeding arbitrarily
    # large strings into the redeem path.
    challenge_id: str = Field(..., min_length=36, max_length=36, pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    action: str = Field(..., min_length=1, max_length=64)
    token: str = Field(..., min_length=16, max_length=2048)


class VerifyTokenResponse(_Base):
    valid: Literal[True]
    challenge_id: str
    action: str


class ErrorResponse(_Base):
    code: str
    detail: str