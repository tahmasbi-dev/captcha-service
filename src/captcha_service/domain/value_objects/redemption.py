from enum import Enum


class RedemptionOutcome(str, Enum):
    """Result of trying to redeem a solved challenge's proof.

    NEW       — consumed now: the challenge existed in the SOLVED state
                and was atomically removed, with this token's verdict
                recorded for a single idempotent retry.
    REPLAY    — a retry with the SAME token found the recorded verdict
                and received it again. The record is consumed by the
                replay itself — it can be replayed exactly once.
    CONFLICT  — the proof was already consumed by a DIFFERENT token;
                this attempt is rejected, so a single solve can never
                yield more than one verdict plus one same-token retry.
    NOT_FOUND — neither a record nor a solved challenge exists.
    """

    NEW = "new"
    REPLAY = "replay"
    CONFLICT = "conflict"
    NOT_FOUND = "not_found"
