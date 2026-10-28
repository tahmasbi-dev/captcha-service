class ApplicationError(Exception):
    """Base for use-case-level failures (mapped to 4xx/5xx at the boundary)."""


class ChallengeNotFound(ApplicationError):
    def __init__(self, challenge_id: object) -> None:
        self.challenge_id = challenge_id
        super().__init__(f"challenge {challenge_id} not found")


class InvalidSolution(ApplicationError):
    """The solution was accepted but did not match. The challenge is burned."""


class InvalidToken(ApplicationError):
    """Malformed, bad signature, or bound to the wrong challenge/action."""


class ExpiredToken(ApplicationError):
    """Signature valid but past `exp`."""