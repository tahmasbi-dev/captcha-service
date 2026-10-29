"""Unit tests for the value objects and the Challenge aggregate — no I/O, no mocks."""
from datetime import datetime, timedelta, timezone

import pytest

from captcha_service.domain.exceptions import (
    InvalidAction,
    InvalidChallengeId,
    InvalidProof,
    InvalidChallengeState,
)
from captcha_service.domain.value_objects.action import Action
from captcha_service.domain.value_objects.challenge_id import ChallengeId
from captcha_service.domain.value_objects.proof import Proof
from captcha_service.domain.value_objects.state import State


# ---- Action ----
def test_action_accepts_slug():
    assert Action.from_str("login").value == "login"
    assert Action.from_str("password_reset_2").value == "password_reset_2"


@pytest.mark.parametrize("bad", ["", "Login", "9lives", "with-dash", "with space", "a" * 65])
def test_action_rejects_bad_slugs(bad):
    with pytest.raises(InvalidAction):
        Action.from_str(bad)


def test_action_equality_is_value_based():
    assert Action.from_str("login") == Action.from_str("login")
    assert Action.from_str("login") != Action.from_str("logout")


# ---- ChallengeId ----
def test_challenge_id_round_trip():
    cid = ChallengeId.new()
    assert ChallengeId.from_str(str(cid)) == cid


def test_challenge_id_is_uuid4():
    assert ChallengeId.new().value.version == 4


@pytest.mark.parametrize("bad", ["", "not-a-uuid", "x" * 36])
def test_challenge_id_rejects_garbage(bad):
    with pytest.raises(InvalidChallengeId):
        ChallengeId.from_str(bad)


# ---- Proof ----
def test_proof_commits_a_digest_not_the_plaintext():
    proof = Proof.from_solution(action=Action.from_str("login"), solution="ABC123")
    assert isinstance(proof.solution_hash, bytes)
    assert len(proof.solution_hash) == 32
    assert b"ABC123" not in proof.solution_hash


def test_proof_matches_exact_solution():
    proof = Proof.from_solution(action=Action.from_str("login"), solution="ABC123")
    assert proof.matches(action=Action.from_str("login"), solution="ABC123")
    assert not proof.matches(action=Action.from_str("login"), solution="ABC124")


def test_proof_requires_action_match():
    proof = Proof.from_solution(action=Action.from_str("login"), solution="ABC123")
    assert not proof.matches(action=Action.from_str("logout"), solution="ABC123")


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(action="login", solution=""),                 # empty solution
        dict(action="login", solution=None),               # non-string
    ],
)
def test_proof_from_solution_rejects_garbage(kwargs):
    with pytest.raises(InvalidProof):
        Proof.from_solution(
            action=Action.from_str(kwargs["action"]), solution=kwargs["solution"]
        )


def test_proof_rejects_wrong_hash_length():
    with pytest.raises(InvalidProof):
        Proof(action=Action.from_str("login"), solution_hash=b"\x00" * 31)


# ---- State ----
def test_issued_can_move_to_solved_expired_or_failed():
    issued = State.issued()
    assert issued.can_transition_to(State.solved())
    assert issued.can_transition_to(State.expired())
    assert issued.can_transition_to(State.failed())


def test_terminal_states_have_no_outgoing_transitions():
    for terminal in (State.solved(), State.expired(), State.failed()):
        assert terminal.is_terminal
        assert not terminal.can_transition_to(State.issued())
        assert not terminal.can_transition_to(State.solved())


def test_illegal_transition_raises():
    with pytest.raises(InvalidChallengeState):
        State.solved().fail()


def test_state_round_trips_through_str():
    for state in (State.issued(), State.solved(), State.expired(), State.failed()):
        assert State.from_str(state.value) == state


def test_unknown_state_string_raises():
    with pytest.raises(InvalidChallengeState):
        State.from_str("bananas")


# ---- Challenge aggregate ----
from captcha_service.domain.entities.challenge import Challenge

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
TTL = timedelta(minutes=5)


def _issue(action="login", solution="ABC123", ttl=TTL, now=NOW):
    return Challenge.issue(
        action=Action.from_str(action), solution=solution, now=now, ttl=ttl
    )


def test_issue_starts_issued_with_version_zero():
    ch = _issue()
    assert ch.state.is_issued
    assert ch._version == 0
    assert ch.expires_at == NOW + TTL


def test_issue_rejects_zero_ttl():
    with pytest.raises(InvalidChallengeState):
        Challenge.issue(action=Action.from_str("login"), solution="X", now=NOW, ttl=timedelta(0))


def test_correct_solution_transitions_to_solved():
    ch = _issue()
    ch.accept_solution(action=Action.from_str("login"), solution="ABC123", now=NOW)
    assert ch.state.is_solved


def test_wrong_solution_burns_to_failed_without_raising():
    ch = _issue()
    ch.accept_solution(action=Action.from_str("login"), solution="WRONG", now=NOW)
    assert ch.state.is_failed


def test_wrong_action_burns_too():
    ch = _issue()
    ch.accept_solution(action=Action.from_str("logout"), solution="ABC123", now=NOW)
    assert ch.state.is_failed


def test_solve_after_solved_is_idempotent_not_an_error():
    ch = _issue()
    ch.accept_solution(action=Action.from_str("login"), solution="ABC123", now=NOW)
    ch.accept_solution(action=Action.from_str("login"), solution="WRONG", now=NOW)
    assert ch.state.is_solved          # wrong answer on a solved challenge changes nothing


def test_solve_after_failed_is_rejected():
    ch = _issue()
    ch.accept_solution(action=Action.from_str("login"), solution="WRONG", now=NOW)
    with pytest.raises(InvalidChallengeState):
        ch.accept_solution(action=Action.from_str("login"), solution="ABC123", now=NOW)


def test_solve_after_expiry_leaves_challenge_expired():
    ch = _issue()
    after_expiry = NOW + TTL
    # accept_solution syncs state first, so past expiry a correct answer
    # cannot resurrect the challenge: it raises, with the state now expired.
    with pytest.raises(InvalidChallengeState):
        ch.accept_solution(action=Action.from_str("login"), solution="ABC123", now=after_expiry)
    assert ch.state.is_expired


def test_expire_before_deadline_raises():
    ch = _issue()
    with pytest.raises(InvalidChallengeState):
        ch.expire(now=NOW + timedelta(seconds=1))


def test_expire_after_deadline_transitions_once():
    ch = _issue()
    ch.expire(now=NOW + TTL)
    assert ch.state.is_expired
    ch.expire(now=NOW + TTL)           # idempotent second call
    assert ch.state.is_expired


def test_should_expire_and_effective_state():
    ch = _issue()
    assert not ch.should_expire(now=NOW)
    assert ch.effective_state(now=NOW).is_issued
    assert ch.should_expire(now=NOW + TTL)
    assert ch.effective_state(now=NOW + TTL).is_expired
    assert ch.state.is_issued          # read paths must not mutate
