"""Use-case unit tests over fake ports — no Redis, no real HTTP.

The fakes are tiny in-memory implementations of the ports. The fake
repository reproduces the port's decision semantics (including
ALREADY_SOLVED idempotency) so the use-case layer's branching is
exercised honestly rather than mocked out.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence

import pytest

from captcha_service.application.dtos.captcha import (
    NewChallengeCommand,
    SolveChallengeCommand,
    VerifyTokenCommand,
)
from captcha_service.application.exceptions import (
    ChallengeNotFound,
    ExpiredToken,
    InvalidSolution,
    InvalidToken,
)
from captcha_service.application.ports.captcha_generator import CaptchaGenerator
from captcha_service.application.ports.challenge_images import ChallengeImageStore
from captcha_service.application.ports.clock import Clock
from captcha_service.application.ports.metrics import UsageMetrics
from captcha_service.application.ports.token import TokenClaims, TokenIssuer, TokenVerifier
from captcha_service.application.use_cases.get_challenge_image import GetChallengeImage
from captcha_service.application.use_cases.get_new_challenge import GetNewChallenge
from captcha_service.application.use_cases.solve_challenge import SolveChallenge
from captcha_service.application.use_cases.verify_token import VerifyToken
from captcha_service.domain.entities.challenge import Challenge
from captcha_service.domain.exceptions import InvalidAction, InvalidChallengeId, InvalidChallengeState
from captcha_service.domain.ports.challenge_repository import ChallengeRepository
from captcha_service.domain.ports.proof_ledger import ProofLedger
from captcha_service.domain.value_objects.action import Action
from captcha_service.domain.value_objects.challenge_id import ChallengeId
from captcha_service.domain.value_objects.redemption import RedemptionOutcome
from captcha_service.domain.value_objects.solve_outcome import SolveOutcome


NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


class FakeClock(Clock):
    def __init__(self, now: datetime = NOW) -> None:
        self.now_value = now

    def now(self) -> datetime:
        return self.now_value


class FakeCaptcha(CaptchaGenerator):
    """Deterministic generator: always the same code, marker bytes for PNG."""

    def __init__(self, code: str = "ABC123") -> None:
        self.code = code

    def generate(self) -> str:
        return self.code

    def render(self, solution: str) -> bytes:
        return b"\x89PNG" + solution.encode()


class FakeImageStore(ChallengeImageStore):
    def __init__(self) -> None:
        self.saved: dict[str, tuple[bytes, int]] = {}

    async def save(self, challenge_id: ChallengeId, png: bytes, ttl_seconds: int) -> None:
        self.saved[str(challenge_id)] = (png, ttl_seconds)

    async def load(self, challenge_id: ChallengeId) -> bytes | None:
        return self.saved.get(str(challenge_id), (None, 0))[0]


class InMemoryChallengeRepository(ChallengeRepository):
    """Same decision rules as the port demands, without concurrency safety."""

    def __init__(self) -> None:
        self.rows: dict[str, Challenge] = {}

    async def get(self, challenge_id: ChallengeId) -> Challenge | None:
        return self.rows.get(str(challenge_id))

    async def save(self, challenge: Challenge) -> None:
        self.rows[str(challenge.id)] = challenge
        challenge._version += 1

    async def find_due_for_expiry(self, now: datetime, limit: int = 100) -> Sequence[Challenge]:
        due = [c for c in self.rows.values() if c.should_expire(now)]
        return due[:limit]

    async def attempt_solve(
        self, challenge_id: ChallengeId, action: Action, solution_sha256_hex: str, *, now: datetime
    ) -> SolveOutcome:
        challenge = self.rows.get(str(challenge_id))
        if challenge is None:
            return SolveOutcome.NOT_FOUND
        import hashlib

        digest_hex = challenge.proof.solution_hash.hex()
        if challenge.state.is_solved:
            return SolveOutcome.ALREADY_SOLVED
        if not challenge.state.is_issued:
            return SolveOutcome.NOT_SOLVABLE
        if challenge.should_expire(now):
            challenge._state = challenge.state.expire()
            challenge._version += 1
            return SolveOutcome.EXPIRED
        if challenge.proof.action != action or digest_hex != solution_sha256_hex:
            challenge._state = challenge.state.fail()
            challenge._version += 1
            return SolveOutcome.WRONG
        challenge._state = challenge.state.solve()
        challenge._version += 1
        return SolveOutcome.SOLVED


class RecordingMetrics(UsageMetrics):
    def __init__(self) -> None:
        self.redeems: list[RedemptionOutcome] = []
        self.solves: list[bool] = []

    def record_redeem(self, outcome: RedemptionOutcome) -> None:
        self.redeems.append(outcome)

    def record_solve(self, solved: bool) -> None:
        self.solves.append(solved)


class StickyTokenService(TokenIssuer, TokenVerifier):
    """Encodes the claims into the token string; verifies by parsing them back.

    Each issue is independently serialized, so re-minting the same claims
    produces a *different* token string — matching how a real JWT differs
    per iat second and per signature."""

    def __init__(self) -> None:
        self.issued: list[TokenClaims] = []
        self._serial = 0

    def issue(self, claims: TokenClaims) -> str:
        self.issued.append(claims)
        self._serial += 1
        return (
            f"tok|{self._serial}|{claims.challenge_id}"
            f"|{claims.action.value}|{int(claims.expires_at.timestamp())}"
        )

    def verify(self, token: str) -> TokenClaims:
        parts = token.split("|")
        # parts: tok | serial | cid | action | exp_ts
        if len(parts) != 5 or parts[0] != "tok":
            raise InvalidToken("malformed token")
        try:
            return TokenClaims(
                challenge_id=ChallengeId.from_str(parts[2]),
                action=Action.from_str(parts[3]),
                issued_at=NOW,
                expires_at=datetime.fromtimestamp(int(parts[4]), tz=timezone.utc),
            )
        except (InvalidChallengeId, InvalidAction, IndexError, ValueError) as exc:
            raise InvalidToken(str(exc)) from exc


class InMemoryLedger(ProofLedger):
    """Records one verdict; one same-token replay; anything else CONFLICT."""

    def __init__(self) -> None:
        self.records: dict[str, tuple[str, str]] = {}   # cid -> (token, action)
        self.challenges: dict[str, str] = {}            # cid -> state

    async def redeem(self, challenge_id: ChallengeId, action: Action, token: str) -> RedemptionOutcome:
        cid = str(challenge_id)
        existing = self.records.get(cid)
        if existing is not None:
            self.records.pop(cid)   # the replay consumes the record, as in Redis
            return RedemptionOutcome.REPLAY if existing[0] == token else RedemptionOutcome.CONFLICT
        if self.challenges.get(cid) == "solved":
            self.challenges.pop(cid)
            self.records[cid] = (token, action.value)
            return RedemptionOutcome.NEW
        return RedemptionOutcome.NOT_FOUND


# ---- GetNewChallenge ----
async def test_get_new_challenge_issues_and_persists_image():
    repo = InMemoryChallengeRepository()
    images = FakeImageStore()
    use = GetNewChallenge(
        repo=repo, captcha=FakeCaptcha(), clock=FakeClock(), ttl=timedelta(minutes=5),
        images=images, image_ttl=timedelta(minutes=15),
    )

    result = await use.execute(NewChallengeCommand(action="login"))

    stored = repo.rows[result.challenge_id]
    assert stored.state.is_issued
    assert stored.proof.action == Action.from_str("login")
    # plaintext never persisted
    assert "ABC123" not in stored.proof.solution_hash.hex()
    assert images.saved[result.challenge_id][0].startswith(b"\x89PNG")
    assert result.expires_at == NOW + timedelta(minutes=5)
    assert result.payload.startswith(b"\x89PNG")


@pytest.mark.parametrize("bad_action", ["", "Login", "no-dashes", "a" * 65])
async def test_get_new_challenge_rejects_bad_action(bad_action):
    use = GetNewChallenge(
        repo=InMemoryChallengeRepository(), captcha=FakeCaptcha(), clock=FakeClock(),
        ttl=timedelta(minutes=5), images=FakeImageStore(), image_ttl=timedelta(minutes=15),
    )
    with pytest.raises(InvalidAction):
        await use.execute(NewChallengeCommand(action=bad_action))


# ---- SolveChallenge ----
def _solve_use(repo, tokens=None, metrics=None, clock=None):
    return SolveChallenge(
        repo=repo,
        tokens=tokens or StickyTokenService(),
        clock=clock or FakeClock(),
        token_ttl=timedelta(minutes=5),
        metrics=metrics or RecordingMetrics(),
    )


async def test_solve_correct_answer_returns_bound_token():
    repo = InMemoryChallengeRepository()
    images = FakeImageStore()
    await GetNewChallenge(
        repo=repo, captcha=FakeCaptcha(), clock=FakeClock(), ttl=timedelta(minutes=5),
        images=images, image_ttl=timedelta(minutes=15),
    ).execute(NewChallengeCommand(action="login"))

    cid = next(iter(repo.rows))
    tokens = StickyTokenService()
    result = await _solve_use(repo, tokens=tokens).execute(
        SolveChallengeCommand(challenge_id=cid, action="login", solution="ABC123")
    )

    assert repo.rows[cid].state.is_solved
    assert len(tokens.issued) == 1
    assert tokens.issued[0].challenge_id.value == ChallengeId.from_str(cid).value
    assert tokens.issued[0].action.value == "login"
    assert result.token.startswith("tok|")
    assert result.expires_at == NOW + timedelta(minutes=5)


async def test_solve_wrong_answer_raises_and_burns():
    repo = InMemoryChallengeRepository()
    images = FakeImageStore()
    await GetNewChallenge(
        repo=repo, captcha=FakeCaptcha(), clock=FakeClock(), ttl=timedelta(minutes=5),
        images=images, image_ttl=timedelta(minutes=15),
    ).execute(NewChallengeCommand(action="login"))
    cid = next(iter(repo.rows))
    metrics = RecordingMetrics()

    with pytest.raises(InvalidSolution):
        await _solve_use(repo, metrics=metrics).execute(
            SolveChallengeCommand(challenge_id=cid, action="login", solution="WRONG")
        )
    assert repo.rows[cid].state.is_failed
    assert metrics.solves == [False]


async def test_solve_again_on_solved_re_mints_token_from_existing_state():
    repo = InMemoryChallengeRepository()
    images = FakeImageStore()
    await GetNewChallenge(
        repo=repo, captcha=FakeCaptcha(), clock=FakeClock(), ttl=timedelta(minutes=5),
        images=images, image_ttl=timedelta(minutes=15),
    ).execute(NewChallengeCommand(action="login"))
    cid = next(iter(repo.rows))
    use = _solve_use(repo)
    await use.execute(SolveChallengeCommand(challenge_id=cid, action="login", solution="ABC123"))
    version_before = repo.rows[cid]._version

    result = await use.execute(SolveChallengeCommand(challenge_id=cid, action="login", solution="ABC123"))

    assert result.token.startswith("tok|")
    assert repo.rows[cid]._version == version_before   # no write churn on retry


async def test_solve_unknown_id_and_bad_id_shapes():
    repo = InMemoryChallengeRepository()
    with pytest.raises(ChallengeNotFound):
        await _solve_use(repo).execute(
            SolveChallengeCommand(challenge_id=str(ChallengeId.new()), action="login", solution="X")
        )
    with pytest.raises(InvalidChallengeId):
        await _solve_use(repo).execute(
            SolveChallengeCommand(challenge_id="not-a-uuid", action="login", solution="X")
        )


async def test_solve_bad_action_raises():
    repo = InMemoryChallengeRepository()
    with pytest.raises(InvalidAction):
        await _solve_use(repo).execute(
            SolveChallengeCommand(challenge_id=str(ChallengeId.new()), action="Login!", solution="X")
        )


# ---- VerifyToken ----
def _verify_use(ledger, tokens=None, metrics=None):
    return VerifyToken(verifier=tokens or StickyTokenService(), ledger=ledger, metrics=metrics or RecordingMetrics())


async def test_verify_first_call_consumes_and_second_same_token_replays_once():
    ledger = InMemoryLedger()
    tokens = StickyTokenService()
    use = _verify_use(ledger, tokens=tokens)
    claims = TokenClaims(challenge_id=ChallengeId.new(), action=Action.from_str("login"),
                         issued_at=NOW, expires_at=NOW + timedelta(minutes=5))
    ledger.challenges[str(claims.challenge_id)] = "solved"
    token = tokens.issue(claims)

    first = await use.execute(VerifyTokenCommand(challenge_id=str(claims.challenge_id), action="login", token=token))
    assert first.valid is True

    # same token retry survives ONE time (network-retry semantics)
    second = await use.execute(VerifyTokenCommand(challenge_id=str(claims.challenge_id), action="login", token=token))
    assert second.valid is True

    # a third attempt is a definitive miss
    with pytest.raises(ChallengeNotFound):
        await use.execute(VerifyTokenCommand(challenge_id=str(claims.challenge_id), action="login", token=token))


async def test_verify_with_different_token_after_consumption_is_rejected():
    ledger = InMemoryLedger()
    tokens = StickyTokenService()
    use = _verify_use(ledger, tokens=tokens)
    claims = TokenClaims(challenge_id=ChallengeId.new(), action=Action.from_str("login"),
                         issued_at=NOW, expires_at=NOW + timedelta(minutes=5))
    ledger.challenges[str(claims.challenge_id)] = "solved"
    token = tokens.issue(claims)
    await use.execute(VerifyTokenCommand(challenge_id=str(claims.challenge_id), action="login", token=token))

    other = tokens.issue(claims)   # re-minted token, same challenge
    with pytest.raises(InvalidToken):
        await use.execute(VerifyTokenCommand(challenge_id=str(claims.challenge_id), action="login", token=other))


async def test_verify_bindings_must_match_token_claims():
    ledger = InMemoryLedger()
    tokens = StickyTokenService()
    use = _verify_use(ledger, tokens=tokens)
    claims = TokenClaims(challenge_id=ChallengeId.new(), action=Action.from_str("login"),
                         issued_at=NOW, expires_at=NOW + timedelta(minutes=5))
    token = tokens.issue(claims)

    with pytest.raises(InvalidToken):
        await use.execute(VerifyTokenCommand(
            challenge_id=str(ChallengeId.new()), action="login", token=token))    # wrong challenge
    with pytest.raises(InvalidToken):
        await use.execute(VerifyTokenCommand(
            challenge_id=str(claims.challenge_id), action="logout", token=token))  # wrong action


async def test_verify_metrics_record_outcomes():
    ledger = InMemoryLedger()
    metrics = RecordingMetrics()
    tokens = StickyTokenService()
    use = _verify_use(ledger, tokens=tokens, metrics=metrics)
    claims = TokenClaims(challenge_id=ChallengeId.new(), action=Action.from_str("login"),
                         issued_at=NOW, expires_at=NOW + timedelta(minutes=5))
    ledger.challenges[str(claims.challenge_id)] = "solved"
    token = tokens.issue(claims)

    await use.execute(VerifyTokenCommand(challenge_id=str(claims.challenge_id), action="login", token=token))
    assert metrics.redeems == [RedemptionOutcome.NEW]


# ---- GetChallengeImage ----
async def test_get_challenge_image_round_trips_bytes():
    images = FakeImageStore()
    cid = str(ChallengeId.new())
    await images.save(ChallengeId.from_str(cid), b"\x89PNG-bytes", 600)
    result = await GetChallengeImage(images=images).execute(cid)
    assert result == b"\x89PNG-bytes"


# ---- ExpiredToken path through the use case ----
class ExpiryThrowingVerifier(TokenVerifier):
    def verify(self, token: str) -> TokenClaims:
        raise ExpiredToken("token expired")


async def test_verify_propagates_expired_token():
    use = VerifyToken(verifier=ExpiryThrowingVerifier(), ledger=InMemoryLedger(), metrics=RecordingMetrics())
    with pytest.raises(ExpiredToken):
        await use.execute(VerifyTokenCommand(
            challenge_id=str(ChallengeId.new()), action="login", token="whatever"))
