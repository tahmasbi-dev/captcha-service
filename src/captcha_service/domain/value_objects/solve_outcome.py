from enum import Enum


class SolveOutcome(str, Enum):
    """What a single atomic solve attempt at the store resolved to.

    The codes mirror what one Lua script can decide without any
    network round trip in between: read the stored state, then commit
    the one transition it legally allows.

    Solving again on an already-solved challenge replays success without
    a write; everything else burns or denies exactly as the domain rules
    prescribe.
    """

    SOLVED = "solved"
    ALREADY_SOLVED = "already_solved"   # idempotent retry: fresh token, zero writes
    WRONG = "wrong"                     # bad solution or wrong action: burned
    EXPIRED = "expired"                 # was issued, time is up: expired in place
    NOT_SOLVABLE = "not_solvable"       # terminal (failed/expired): nothing to do
    NOT_FOUND = "not_found"             # absent, TTL'd, or already consumed
