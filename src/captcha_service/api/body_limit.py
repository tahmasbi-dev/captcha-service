from __future__ import annotations

import json
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

log = logging.getLogger(__name__)

_DEFAULT_MAX_BODY_BYTES = 16 * 1024  # 16 KiB: generous for captcha payloads


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject request bodies above a small ceiling with 413.

    Every endpoint here takes at most a few hundred bytes (a 6-char
    solution, a JWT, an action name). Anything larger is not a real
    client — with no ceiling, any caller can hand uvicorn an
    arbitrarily large body to buffer. Checked from Content-Length
    before reading, so the body is never even pulled off the wire.
    Chunked requests without Content-Length are guarded while they are
    being read; the counter trips mid-stream and aborts.
    """

    def __init__(self, app, max_body_bytes: int = _DEFAULT_MAX_BODY_BYTES) -> None:
        super().__init__(app)
        self.max_body_bytes = max_body_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.max_body_bytes:
                    return Response(
                        status_code=413,
                        content=json.dumps(
                            {"code": "payload_too_large", "detail": f"body exceeds {self.max_body_bytes} bytes"}
                        ),
                        media_type="application/json",
                    )
            except ValueError:
                return Response(status_code=400)

        # Guard chunked bodies by clamping the receive stream.
        response = await call_next(_ClampedBodyRequest(request, self.max_body_bytes))
        return response


class _ClampedBodyRequest:
    """Request wrapper whose body stream truncates at the limit.

    We don't truncate silently — the wrapped stream over-reads by one
    chunk and then raises, which surfaces as a 413 via the normal
    exception path (validation reads run inside route handling).
    """

    def __init__(self, request: Request, max_body_bytes: int) -> None:
        self._request = request
        self._max = max_body_bytes

    def __getattr__(self, name):
        return getattr(self._request, name)

    async def stream(self):
        received = 0
        async for chunk in self._request.stream():
            received += len(chunk)
            if received > self._max:
                raise _BodyTooLargeError(self._max)
            yield chunk


class _BodyTooLargeError(Exception):
    pass
