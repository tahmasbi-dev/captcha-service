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
    """Use the route template as the histogram label, not the raw path.

    Raw client paths would explode the label cardinality (404s, junk
    paths, ids), so anything that never reached routing is just
    'unmatched'.
    """
    route = scope.get("route")
    return route.path if route is not None else "unmatched"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """One request id, one latency sample, one access-log line, per request.

    An incoming X-Request-ID is reused (proxies in front of us usually
    set one); otherwise a 32-hex id is minted, and the response echoes
    it back so callers can quote it in bug reports. Every request
    lands in the latency histogram, including ones that raise on the
    way out. Redis failures are counted centrally; anything else
    unexpected gets a traceback in the log and is re-raised for the 500.
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
