import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from captcha_service.application.exceptions import (
    ChallengeNotFound,
    ExpiredToken,
    InvalidSolution,
    InvalidToken,
)
from captcha_service.domain.exceptions import (
    DomainError,
    InvalidAction,
    InvalidChallengeId,
    InvalidChallengeState,
    StaleChallenge,
)

log = logging.getLogger(__name__)


def _body(code: str, detail: str) -> dict:
    return {"code": code, "detail": detail}


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ChallengeNotFound)
    async def _(request: Request, exc: ChallengeNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content=_body("challenge_not_found", str(exc)))

    @app.exception_handler(InvalidSolution)
    async def _(request: Request, exc: InvalidSolution) -> JSONResponse:
        # The challenge is already FAILED in storage; the client must re-request.
        return JSONResponse(
            status_code=400,
            content=_body(
                "invalid_solution",
                "solution did not match; the challenge is now invalidated",
            ),
        )

    @app.exception_handler(InvalidChallengeId)
    async def _(request: Request, exc: InvalidChallengeId) -> JSONResponse:
        return JSONResponse(status_code=400, content=_body("invalid_challenge_id", str(exc)))

    @app.exception_handler(InvalidAction)
    async def _(request: Request, exc: InvalidAction) -> JSONResponse:
        return JSONResponse(status_code=400, content=_body("invalid_action", str(exc)))

    @app.exception_handler(InvalidToken)
    async def _(request: Request, exc: InvalidToken) -> JSONResponse:
        return JSONResponse(status_code=400, content=_body("invalid_token", str(exc)))

    @app.exception_handler(ExpiredToken)
    async def _(request: Request, exc: ExpiredToken) -> JSONResponse:
        return JSONResponse(status_code=401, content=_body("expired_token", str(exc)))

    @app.exception_handler(StaleChallenge)
    async def _(request: Request, exc: StaleChallenge) -> JSONResponse:
        # Concurrent mutation lost the CAS race. Client may retry with a fresh challenge.
        return JSONResponse(
            status_code=409,
            content=_body("stale_challenge", "challenge was modified concurrently; request a new one"),
        )

    @app.exception_handler(InvalidChallengeState)
    async def _(request: Request, exc: InvalidChallengeState) -> JSONResponse:
        return JSONResponse(status_code=409, content=_body("invalid_state", str(exc)))

    @app.exception_handler(DomainError)
    async def _(request: Request, exc: DomainError) -> JSONResponse:
        # Catch-all: a DomainError we didn't map explicitly = a bug we need to see.
        log.exception("unmapped domain error", exc_info=exc)
        return JSONResponse(status_code=422, content=_body("domain_error", str(exc)))