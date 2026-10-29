"""Conftest for integration + e2e tests.

Integration tests share the dev compose Redis on loopback: database 1
for adapter tests, database 2 for the HTTP e2e ones, with those dbs
flushed per session. The running app keeps its data in db 0, which
the tests never touch.
"""
import os
from collections.abc import AsyncIterator

import pytest
from redis.asyncio import Redis

# Loopback by default (dev compose); CI or other hosts point the env vars elsewhere.
API_REDIS = os.environ.get("API_TEST_REDIS_URL", "redis://127.0.0.1:6379/1")
E2E_REDIS = os.environ.get("E2E_TEST_REDIS_URL", "redis://127.0.0.1:6379/2")

TEST_INTERNAL_KEY = "t" * 32 + "internal-key"
TEST_JWT_SECRET = "s" * 32 + "jwt-secret"


@pytest.fixture(scope="session")
def integration_url() -> str:
    return API_REDIS


@pytest.fixture(scope="session")
def e2e_url() -> str:
    return E2E_REDIS


@pytest.fixture(scope="session")
def settings_kwargs() -> dict:
    return {
        "internal_api_key": TEST_INTERNAL_KEY,
        "jwt_secret": TEST_JWT_SECRET,
        "_env_file": None,
    }


@pytest.fixture
async def redis(integration_url: str) -> AsyncIterator[Redis]:
    client = Redis.from_url(integration_url, decode_responses=True)
    await client.flushdb()
    yield client
    await client.flushdb()
    await client.aclose()
