from __future__ import annotations

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from captcha_service.domain.value_objects.challenge_id import ChallengeId
    
class DomainError(Exception):
    """Base class for every business rule violation."""

class ChallengeError(DomainError):
    """Base for Challenge aggregate violations."""

class InvalidAction(ChallengeError):
    """The supplied action is not a valid Action."""
    
class InvalidChallengeState(DomainError):
    """The State of the challenge is invalid."""

class InvalidChallengeId(ChallengeError):
    "The challenge id is invalid."

class InvalidProof(ChallengeError):
    """The Proof VO was constructed with invalid inputs."""
    
class StaleChallenge(ChallengeError):
    """The aggregate was modified concurrently; the caller must reload and decide.

    Raised by the repository adapter when the optimistic-concurrency check
    fails — i.e. the version stored in Redis no longer matches the version
    the caller loaded. The entity's in-memory state is *not* authoritative;
    it represents a write that lost the race and must be discarded.
    """

    def __init__(self, challenge_id: ChallengeId) -> None:
        self.challenge_id = challenge_id
        super().__init__(
            f"challenge {challenge_id} was modified concurrently"
        )