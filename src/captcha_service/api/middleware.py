from __future__ import annotations

import logging
import time
from uuid import uuid4

from redis.exceptions import RedisError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from captcha_service.core.logging_setup import request_id_var
from captcha_service.infrastructure import observability

log = logging.getLogger("captcha_service.request")


def _path_label(scope: dict) -> str:
    """Route template keeps the cardinality of the histogram bounded.

    Falls back to a fixed 'unmatched' label for 404s and errors that
    never reach routing — raw client paths would multiply label series.
    """
    route = scope.get("route")
    return route.path if route is not None else "unmatched"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """One request id, one latency sample, one access-log line, per request.

    - Honours an incoming X-Request-ID (callers behind a proxy usually
      already set one); mints a 32-hex id otherwise. The response echoes
      it back so a client can quote it in a report.
    - Every request lands in the latency histogram, incl. handled
      exceptions (their responses still flow through here).
    - Redis failures are counted centrally; anything else unexpected is
      logged with a traceback and re-raised for the 500.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        rid = request.headers.get("x-request-id") or uuid4().hex
        request_id_var.set(rid)
        method = request.method
        started = time.perf_counter()

        try:
            response = await call_next(request)
        except RedisError:
            elapsed = time.perf_counter() - started
            observability.record_redis_error()
            observability.request_latency(method, _path_label(request.scope), 500, elapsed)
            log.exception("redis failure while serving request", extra={
                "ctx": {"method": method, "path": request.url.path},
            })
            raise
        except Exception:
            elapsed = time.perf_counter() - started
            observability.request_latency(method, _path_label(request.scope), 500, elapsed)
            log.exception("unhandled request failure", extra={
                "ctx": {"method": method, "path": request.url.path},
            })
            raise

        elapsed = time.perf_counter() - started
        status = response.status_code
        path_label = _path_label(request.scope)
        observability.request_latency(method, path_label, status, elapsed)
        response.headers["X-Request-ID"] = rid
        log.info("http request", extra={"ctx": {
            "method": method,
            "path": path_label,
            "status": status,
            "duration_ms": round(elapsed * 1000, 1),
        }})
        return response
