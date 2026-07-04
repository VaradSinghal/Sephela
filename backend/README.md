# Sephela Backend — API Gateway / Core Service

FastAPI foundation (Phase 2). Clean, extensible base with **no malware logic yet**.

## What's here
- **FastAPI** app with versioned `/api/v1`, OpenAPI, CORS.
- **Config** — 12-factor, env-driven, validated (`app/core/config.py`).
- **Structured logging** — structlog JSON/console, trace-id per request.
- **Exception handling** — RFC 9457 Problem Details (`application/problem+json`).
- **Auth placeholder** — JWT issue/verify + `get_current_user` dep + RBAC roles
  (OIDC/SSO slots in behind the same dependency later).
- **Database** — async SQLAlchemy 2.0 + asyncpg; Alembic migrations (async env).
- **Background tasks** — Celery + Redis with per-workload-class queues.
- **Health** — `/health/live`, `/health/ready` (checks Postgres + Redis).
- **Docker** — non-root image; `infra/compose` local full stack.

## Run locally (Docker — recommended)
```bash
make up          # postgres + redis + api (auto-migrates) + worker
# API:   http://localhost:8000
# Docs:  http://localhost:8000/docs
```

## Run without Docker
```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env            # then edit SEPHELA_SECRET_KEY
alembic revision --autogenerate -m "initial"   # needs Postgres running
alembic upgrade head
uvicorn app.main:app --reload
```

## Test / lint / type
```bash
make test    # pytest
make lint    # ruff
make type    # mypy
```

## Layout
```
app/
  api/v1/routers/   # auth (placeholder), health
  core/             # config, logging, exceptions, middleware, security, redis
  db/               # base, session, models/ (identity only for now)
  schemas/          # pydantic request/response
  services/ repositories/ storage/ events/   # reserved for later phases
  tasks/            # celery app + queues + health task
alembic/            # async migration env
```

## Notes
- Analysis-domain models (samples, jobs, evidence, findings…) are intentionally
  **not** created yet — see docs/architecture/04-data-model.md; they arrive with
  their phases. Only identity/tenancy (orgs, users, RBAC) is modeled now.
- Auth endpoints are placeholders: `/auth/login` mints a token without verifying
  credentials so the surface is stable for the frontend and integrations.
