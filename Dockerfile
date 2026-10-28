# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim

WORKDIR /app

ENV UV_DEFAULT_INDEX=https://package-mirror.liara.ir/repository/pypi/simple/

# Install locked dependencies
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-editable

COPY README.md ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-editable

# .env is mounted/injected by compose (env_file); never bake secrets into the image.
EXPOSE 8000
CMD ["/app/.venv/bin/uvicorn", "captcha_service.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
