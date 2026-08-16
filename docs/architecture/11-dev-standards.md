# Development Standards

## Language & style
- **Python 3.12**, `ruff` (lint+format), `mypy --strict`, `black`-compatible.
  Type hints mandatory on public functions. Google-style docstrings.
- **TypeScript strict**, `eslint` + `prettier`, no `any` without justification.
- Naming: `snake_case` (py), `camelCase`/`PascalCase` (ts), `kebab-case` files (fe).
- **Thin controllers, fat services, isolated repositories.** No business logic in
  routers; no DB access outside repositories.

## Architecture rules (enforced in review + CI)
- Engines depend only on `sephela_evidence` + `sephela_contracts` — **never** import
  backend/worker code (import-linter contract in CI).
- No cross-service DB access; go through APIs/events.
- All cross-boundary payloads defined in `contracts/`; models are generated, not
  hand-written twice.
- Every engine emits a schema-valid Evidence Envelope; validated in CI.

## Configuration
- **12-factor**: config from env, validated via Pydantic `Settings` per service.
- No secrets in code/git; local `.env` (gitignored) + `.env.example` documented.
- Feature flags for phased capabilities (dynamic/TI/RAG/multi-agent on/off per env).

## Logging & observability
- **Structured JSON logs** (structlog); every log carries `job_id`, `trace_id`,
  `org_id` where applicable. No PII/secrets/sample-strings in logs.
- OpenTelemetry tracing across API → queue → workers → engines.
- Standard metrics per service (RED: rate, errors, duration) + queue depth.

## Error handling
- Central exception hierarchy in `sephela_common`; map to Problem Details at API.
- Distinguish transient vs permanent for retry logic. Never swallow exceptions;
  fail closed on security-relevant paths.

## Testing (gates in CI)
| Level | Tool | Requirement |
|---|---|---|
| Unit | pytest / vitest | fast, isolated; coverage floor (e.g. 80% core) |
| Contract | schemathesis / pact | API + envelope conform to `contracts/` |
| Integration | pytest + testcontainers | real Postgres/Redis/MinIO |
| E2E | playwright | key flows: upload → job → report |
| Security | bandit, semgrep, trivy, pip-audit/npm-audit | no high/critical to merge |
| Load | k6 (staging) | meet the SLOs in [infra/load/README.md](../../infra/load/README.md) — reads p95 < 500 ms at ≥ 150 rps; upload accept p95 < 2 s. Thresholds are encoded in the scenarios, so a breach exits non-zero and gates a release. **Not yet calibrated against a deployed environment.** |
| Infra | pytest (`test_k8s_manifests.py`) | manifests parse; selectors, references, and autoscaler targets resolve; security posture and sandbox isolation intact. Does **not** replace `kubectl apply --dry-run=server`. |
- Analysis engines tested with a **curated corpus** (benign + labeled malware) with
  golden Evidence Envelopes; regression on score drift.

## Git & CI/CD
- Trunk-based with short-lived PRs; **Conventional Commits**; squash-merge.
- PR must pass: lint, type, unit, contract, security-scan, import-linter.
- Branch protection + required reviews (≥1, ≥2 for security-sensitive paths).
- Migrations: backward-compatible, reviewed, run as pre-deploy job; no destructive
  change without a documented two-step (expand/contract) migration.

## Documentation
- ADRs (`docs/adr/`) for significant decisions (this doc set seeds them).
- OpenAPI/AsyncAPI kept current (generated); README per service with run/test steps.
- Runbooks for on-call (queues stuck, sandbox escape response, DR).

## Definition of Done
Code + tests + docs updated, contracts valid, security scan clean, observability
(logs/metrics/traces) in place, reviewed, and demoable end-to-end.
