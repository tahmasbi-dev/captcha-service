import hmac
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status

from captcha_service.application.bootstrap import UseCases
from captcha_service.core.settings import Settings


def get_use_cases(request: Request) -> UseCases:
    return request.app.state.use_cases


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


UseCasesDep = Annotated[UseCases, Depends(get_use_cases)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


def require_internal_key(
    settings: SettingsDep,
    x_internal_key: Annotated[str, Header(alias="X-Internal-Key")],
) -> None:
    expected = settings.internal_api_key.get_secret_value()
    if not hmac.compare_digest(x_internal_key, expected):
        # Same response for "wrong key" and "missing key" — don't help attackers.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="unauthorized")


InternalOnly = Depends(require_internal_key)