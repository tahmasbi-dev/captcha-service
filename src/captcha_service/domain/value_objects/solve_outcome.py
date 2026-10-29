from enum import Enum


class SolveOutcome(str, Enum):
    """What a single atomic solve attempt at the store resolved to.

    The codes line up with what one Lua script can decide in a single
    round trip: read the stored state, then commit the one transition
    it legally allows. An already-solved challenge replays success
    without a write; everything else fails or denies per the domain
    rules.
    """

    SOLVED = "solved"
    ALREADY_SOLVED = "already_solved"   # idempotent retry: fresh token, no writes
    WRONG = "wrong"                     # bad solution or wrong action, challenge spent
    EXPIRED = "expired"                 # was issued, time is up, expired in place
    NOT_SOLVABLE = "not_solvable"       # terminal (failed/expired), nothing to do
    NOT_FOUND = "not_found"             # absent, TTL'd out, or already consumed
