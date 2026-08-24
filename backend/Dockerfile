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
    curl unzip default-jre-headless \
    libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libfontconfig1 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L -o jadx.zip https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip \
    && unzip jadx.zip -d /usr/local/jadx \
    && ln -s /usr/local/jadx/bin/jadx /usr/local/bin/jadx \
    && rm jadx.zip

# Backend dependencies first — this layer only busts when deps change.
COPY backend/pyproject.toml ./
RUN pip install --upgrade pip && pip install .

# Analysis engines are separate distributions consumed by worker stages. All five
# are installed because every one of them now has a stage in the pipeline chain —
# a missing install surfaces as a failed stage with a clear message rather than a
# crash, which makes it exactly the kind of gap that survives unnoticed.
COPY engines/static /opt/engines/static
RUN pip install "/opt/engines/static[tools]"
COPY engines/code_intel /opt/engines/code_intel
RUN pip install /opt/engines/code_intel
COPY engines/dynamic /opt/engines/dynamic
RUN pip install /opt/engines/dynamic
COPY engines/threat_intel /opt/engines/threat_intel
RUN pip install /opt/engines/threat_intel
COPY engines/reporting /opt/engines/reporting
RUN pip install "/opt/engines/reporting[pdf]"

# The GenAI subsystem is NOT optional for this image, despite only the AI stage
# using it: app/tasks/pipeline.py imports app.tasks.ai at module scope, and the API
# reaches pipeline through app.events.producer. Without `ai` installed, both the API
# and every worker fail at import with ModuleNotFoundError — not at first AI use.
COPY ai /opt/ai
RUN pip install "/opt/ai[otel]"

COPY backend/ .

# Run as non-root (defense in depth — see docs/architecture/09-security.md).
RUN useradd --create-home --uid 10001 sephela \
    && chown -R sephela:sephela /app
USER sephela

EXPOSE 8000

# Default = API server. Worker overrides the command in docker-compose.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
