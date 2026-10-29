from contextlib import asynccontextmanager
import asyncio

from fastapi import FastAPI
from redis.asyncio import Redis

from captcha_service.api.body_limit import BodySizeLimitMiddleware
from captcha_service.api.errors import register_exception_handlers
from captcha_service.api.middleware import RequestContextMiddleware
from captcha_service.api.routes import operations, router
from captcha_service.application.bootstrap import build_expiry_sweeper, build_limiters, build_use_cases
from captcha_service.core.logging_setup import configure_logging
from captcha_service.core.settings import Settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings()                                       # fails fast if missing
    redis = Redis.from_url(
        settings.redis_url,
        decode_responses=True,
        socket_connect_timeout=settings.redis_socket_connect_timeout,
        socket_timeout=settings.redis_socket_timeout,
        health_check_interval=15,
    )
    app.state.settings = settings
    app.state.redis = redis
    app.state.use_cases = build_use_cases(redis=redis, settings=settings)
    app.state.limiters = build_limiters(redis=redis, settings=settings)

    sweeper_task: asyncio.Task | None = None
    if settings.expiry_sweep_interval_seconds > 0:
        sweeper = build_expiry_sweeper(redis=redis, settings=settings)
        sweeper_task = asyncio.create_task(sweeper.run_forever())

    try:
        yield
    finally:
        if sweeper_task is not None:
            sweeper_task.cancel()
            try:
                await sweeper_task
            except asyncio.CancelledError:
                pass
        await redis.aclose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="captcha-service",
        version="0.1.0",
        lifespan=lifespan,
    )
    configure_logging()
    register_exception_handlers(app)
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(RequestContextMiddleware)
    app.include_router(operations)
    app.include_router(router)
    return app


app = create_app()