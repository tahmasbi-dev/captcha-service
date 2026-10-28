from dataclasses import dataclass
from datetime import datetime


# ---- GetNewChallenge ----
@dataclass(frozen=True, slots=True)
class NewChallengeCommand:
    action: str


@dataclass(frozen=True, slots=True)
class NewChallengeResult:
    challenge_id: str
    payload: bytes
    expires_at: datetime


# ---- SolveChallenge ----
@dataclass(frozen=True, slots=True)
class SolveChallengeCommand:
    challenge_id: str
    action: str
    solution: str


@dataclass(frozen=True, slots=True)
class SolveChallengeResult:
    token: str
    expires_at: datetime


# ---- VerifyToken ----
@dataclass(frozen=True, slots=True)
class VerifyTokenCommand:
    challenge_id: str
    action: str
    token: str


@dataclass(frozen=True, slots=True)
class VerifyTokenResult:
    valid: bool
    challenge_id: str
    action: str