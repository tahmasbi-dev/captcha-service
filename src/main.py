from contextlib import asynccontextmanager

from fastapi import FastAPI
from redis.asyncio import Redis

from captcha_service.application.bootstrap import build_use_cases
from captcha_service.core.settings import Settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings()                                    # ← once
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    app.state.settings = settings
    app.state.use_cases = build_use_cases(redis=redis, settings=settings)
    try:
        yield
    finally:
        await redis.aclose()                                 # ← pool closed


app = FastAPI(lifespan=lifespan)