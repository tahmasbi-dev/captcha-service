from contextlib import asynccontextmanager

from fastapi import FastAPI
from redis.asyncio import Redis

from captcha_service.api.errors import register_exception_handlers
from captcha_service.api.middleware import RequestContextMiddleware
from captcha_service.api.routes import operations, router
from captcha_service.application.bootstrap import build_use_cases
from captcha_service.core.logging_setup import configure_logging
from captcha_service.core.settings import Settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings()                                       # fails fast if missing
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    app.state.settings = settings
    app.state.redis = redis
    app.state.use_cases = build_use_cases(redis=redis, settings=settings)
    try:
        yield
    finally:
        await redis.aclose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="captcha-service",
        version="0.1.0",
        lifespan=lifespan,
    )
    configure_logging()
    register_exception_handlers(app)
    app.add_middleware(RequestContextMiddleware)
    app.include_router(operations)
    app.include_router(router)
    return app


app = create_app()