from enum import Enum


class RedemptionOutcome(str, Enum):
    """Result of trying to redeem a solved challenge's proof.

    NEW       consumed now: the challenge existed in the SOLVED state,
              was atomically removed, and this token's verdict was
              recorded for a single idempotent retry.
    REPLAY    a retry with the SAME token found the recorded verdict
              and got it again. The replay consumes the record, so it
              can happen exactly once.
    CONFLICT  the proof was consumed by a DIFFERENT token; this
              attempt is rejected so one solve can never pay for more
              than one verdict plus one same-token retry.
    NOT_FOUND no record and no solved challenge.
    """

    NEW = "new"
    REPLAY = "replay"
    CONFLICT = "conflict"
    NOT_FOUND = "not_found"
