from datetime import datetime, timezone


class SystemClock:
    """UTC wall clock. Tests inject a fake with `now()` under control."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)