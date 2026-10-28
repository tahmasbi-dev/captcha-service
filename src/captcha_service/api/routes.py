import base64

from fastapi import APIRouter, status

from captcha_service.api.dependencies import InternalOnly, UseCasesDep
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


router = APIRouter(prefix="/v1")

_ERRORS = {
    400: {"model": ErrorResponse, "description": "Bad request (bad token, wrong solution, malformed id)"},
    401: {"model": ErrorResponse, "description": "Expired token / unauthorized"},
    404: {"model": ErrorResponse, "description": "Challenge not found"},
    409: {"model": ErrorResponse, "description": "Challenge is in a non-solvable state / concurrent modification"},
    422: {"model": ErrorResponse, "description": "Request validation failed"},
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
    summary="Verify a solve token (internal — requires X-Internal-Key)",
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

@router.get("/health", include_in_schema=False)
async def health() -> dict[str, str]:
    return {"status": "ok"}