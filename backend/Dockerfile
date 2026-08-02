# syntax=docker/dockerfile:1
# Multi-stage build for the Sephela backend (API + workers share this image).
#
# NOTE: the build context is the REPOSITORY ROOT, not backend/ — the image also
# installs the analysis engine distributions from engines/. Build via
# infra/compose/docker-compose.yml, or from the repo root:
#   docker build -f backend/Dockerfile .
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps kept minimal; add build tooling only in a builder layer if needed.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Backend dependencies first — this layer only busts when deps change.
COPY backend/pyproject.toml ./
RUN pip install --upgrade pip && pip install .

# Analysis engines are separate distributions consumed by worker stages. Each is
# pure-Python (pydantic only), so this stays a cheap layer.
COPY engines/dynamic /opt/engines/dynamic
RUN pip install /opt/engines/dynamic

COPY backend/ .

# Run as non-root (defense in depth — see docs/architecture/09-security.md).
RUN useradd --create-home --uid 10001 sephela \
    && chown -R sephela:sephela /app
USER sephela

EXPOSE 8000

# Default = API server. Worker overrides the command in docker-compose.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
