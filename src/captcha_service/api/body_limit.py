from __future__ import annotations

import json
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

log = logging.getLogger(__name__)

_DEFAULT_MAX_BODY_BYTES = 16 * 1024  # 16 KiB, plenty for these payloads


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject request bodies above a small ceiling with 413.

    The largest legit payload here is a few hundred bytes: a 6-char
    solution, a JWT, an action name. Without a ceiling anybody could
    hand uvicorn an arbitrarily large body to buffer. Content-Length
    is checked before reading anything, so oversized bodies are
    rejected without ever coming off the wire. Chunked requests (no
    Content-Length) are instead counted while reading, and the
    counter aborts mid-stream when it trips.
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
    """Request wrapper whose body stream aborts at the limit.

    It doesn't truncate. The wrapped stream reads one chunk too many,
    raises, and the error surfaces as a 413 through the normal
    exception paths while the route is still consuming the body.
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
