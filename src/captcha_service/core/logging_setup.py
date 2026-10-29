import json
import logging
import sys
from contextvars import ContextVar
from datetime import datetime, timezone

# The request id rides along on every log line emitted while handling a
# request. The middleware picks it up from the X-Request-ID header (or
# mints one) and the response sends it back, so clients can quote it
# in bug reports.
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")

_RESERVED_ATTRS = frozenset({
    "args", "asctime", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "module", "msecs",
    "message", "msg", "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "stacklevel", "thread", "threadName",
    "taskName", "sinfo",
})


class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line. Extra context goes in a dict under 'ctx'."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }
        ctx = getattr(record, "ctx", None)
        if isinstance(ctx, dict):
            payload.update(ctx)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        extras = {k: v for k, v in record.__dict__.items() if k not in _RESERVED_ATTRS}
        for key, value in extras.items():
            if key not in payload and key not in ("ctx", "request_id"):
                try:
                    json.dumps(value)
                    payload[key] = value
                except (TypeError, ValueError):
                    payload[key] = repr(value)
        return json.dumps(payload, default=str)


def configure_logging(level: int = logging.INFO) -> None:
    """Point every logger at the JSON handler, uvicorn's included.

    uvicorn installs its own handlers at import time; we leave them in
    place but swap the formatter so access/error logs stay one format.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(_RequestIdFilter())

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers[:] = [handler]

    for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        for h in logging.getLogger(name).handlers:
            h.setFormatter(JsonFormatter())
            h.addFilter(_RequestIdFilter())
