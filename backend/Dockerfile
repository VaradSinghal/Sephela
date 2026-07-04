# syntax=docker/dockerfile:1
# Multi-stage build for the Sephela backend (API + workers share this image).
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps kept minimal; add build tooling only in a builder layer if needed.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install .

COPY . .

# Run as non-root (defense in depth — see docs/architecture/09-security.md).
RUN useradd --create-home --uid 10001 sephela \
    && chown -R sephela:sephela /app
USER sephela

EXPOSE 8000

# Default = API server. Worker overrides the command in docker-compose.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
