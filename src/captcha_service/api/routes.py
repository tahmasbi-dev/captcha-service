import base64
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from redis.asyncio import Redis
from starlette.responses import JSONResponse, Response

from captcha_service.api.dependencies import (
    InternalOnly,
    RedisDep,
    UseCasesDep,
    limit_challenges,
    limit_solves,
)
from captcha_service.api.schemas import (
    ErrorResponse,
    NewChallengeRequest,
    NewChallengeResponse,
    SolveChallengeRequest,
    SolveChallengeResponse,
    VerifyTokenRequest,
    VerifyTokenResponse,
)
from captcha_service.application.dtos.captcha import (
    NewChallengeCommand,
    SolveChallengeCommand,
    VerifyTokenCommand,
)


from captcha_service.infrastructure import observability


router = APIRouter(prefix="/v1")
operations = APIRouter()      # health + metrics, outside the /v1 surface

_ERRORS = {
    400: {"model": ErrorResponse, "description": "Bad request (bad token, wrong solution, malformed id)"},
    401: {"model": ErrorResponse, "description": "Expired token / unauthorized"},
    404: {"model": ErrorResponse, "description": "Challenge not found"},
    409: {"model": ErrorResponse, "description": "Challenge is in a non-solvable state / concurrent modification"},
    422: {"model": ErrorResponse, "description": "Request validation failed"},
    429: {"model": ErrorResponse, "description": "Rate limit exceeded (Retry-After header)"},
}

@router.post(
    "/challenges",
    response_model=NewChallengeResponse,
    status_code=status.HTTP_201_CREATED,
    responses=_ERRORS,
    summary="Issue a new CAPTCHA challenge",
    tags=["captcha"],
)
async def create_challenge(
    body: NewChallengeRequest,
    use_cases: UseCasesDep,
    _: Annotated[None, Depends(limit_challenges)],
) -> NewChallengeResponse:
    result = await use_cases.get_new_challenge.execute(
        NewChallengeCommand(action=body.action),
    )
    return NewChallengeResponse(
        challenge_id=result.challenge_id,
        image="data:image/png;base64," + base64.b64encode(result.payload).decode("ascii"),
        expires_at=result.expires_at,
    )

@router.post(
    "/challenges/{challenge_id}/solve",
    response_model=SolveChallengeResponse,
    responses=_ERRORS,
    summary="Submit a solution; returns a signed JWT on success",
    tags=["captcha"],
)
async def solve_challenge(
    challenge_id: str,
    body: SolveChallengeRequest,
    use_cases: UseCasesDep,
    _: Annotated[None, Depends(limit_solves)],
) -> SolveChallengeResponse:
    result = await use_cases.solve_challenge.execute(
        SolveChallengeCommand(
            challenge_id=challenge_id,
            action=body.action,
            solution=body.solution,
        ),
    )
    return SolveChallengeResponse(token=result.token, expires_at=result.expires_at)
@router.post(
    "/internal/verify",
    response_model=VerifyTokenResponse,
    responses={401: _ERRORS[401], 400: _ERRORS[400]},
    summary="Verify a solve token (internal; requires X-Internal-Key)",
    tags=["internal"],
    dependencies=[InternalOnly],
)
async def verify_token(
    body: VerifyTokenRequest,
    use_cases: UseCasesDep,
) -> VerifyTokenResponse:
    result = await use_cases.verify_token.execute(
        VerifyTokenCommand(
            challenge_id=body.challenge_id,
            action=body.action,
            token=body.token,
        ),
    )
    return VerifyTokenResponse(
        valid=True,
        challenge_id=result.challenge_id,
        action=result.action,
    )

@operations.get("/health", include_in_schema=False)
@router.get("/health", include_in_schema=False)
async def health(request: Request, redis: RedisDep) -> Response:
    """Liveness with substance: pings Redis and reports Lua script state.

    503 when Redis is unreachable. A captcha service with no store
    can't do its job, so we'd rather fail loud than claim ok.
    """
    report = await observability.redis_healthcheck(redis)
    if not report["redis_up"]:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unavailable",
                "error": report["error"],
                "lua_scripts": report["scripts"],
            },
        )
    return JSONResponse(content={
        "status": "ok",
        "redis": "up",
        "lua_scripts": report["scripts"],
    })


@operations.get("/metrics", include_in_schema=False)
async def metrics(request: Request, redis: RedisDep) -> Response:
    """Prometheus scrape endpoint.

    Latency histograms, redeem outcomes, solve right/wrong, stale CAS
    writes, Redis errors, and a fresh read of the expiry queue. All
    stateless instrument reads or one cheap ZCARD.
    """
    await observability.refresh_expiry_gauge(redis)
    payload, content_type = observability.render_metrics()
    return Response(content=payload, media_type=content_type)


@router.get(
    "/challenges/{challenge_id}/image",
    response_class=Response,
    responses={404: _ERRORS[404], 400: _ERRORS[400]},
    summary="Fetch the rendered challenge image as raw PNG",
    tags=["captcha"],
)
async def challenge_image(
    challenge_id: str,
    request: Request,
    use_cases: UseCasesDep,
) -> Response:
    """Raw PNG bytes instead of a base64 data URL: a third lighter, and
    the browser renders it directly. The image never changes for the
    life of the challenge, so the challenge id works as the ETag and a
    matching If-None-Match gets a cheap 304."""
    payload = await use_cases.get_challenge_image.execute(challenge_id)
    etag = f'"{challenge_id}"'
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    return Response(content=payload, media_type="image/png", headers={"ETag": etag})
