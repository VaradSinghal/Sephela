# Sephela

**Enterprise platform for GenAI-based automated analysis & risk scoring of
fraudulent Android APKs** — built for banking cybersecurity teams.

Ingest suspicious APKs → multi-engine static + dynamic analysis → threat-intel
enrichment → multi-agent GenAI reasoning → explainable risk score → SOC-ready
reports.

## Status
**Phases 1–14 implemented, and all of them now reachable from a running job.**
Architecture, backend, frontend, upload pipeline, static/code-intel/dynamic
engines, GenAI reasoning, risk scoring, reporting, threat-intel enrichment, the RAG
knowledge service, the multi-agent orchestrator, and production hardening are in
place.

The pipeline chain ([backend/app/tasks/pipeline.py](backend/app/tasks/pipeline.py)):

```
intake → static → code_intel → dynamic → threat_intel
       → [ai, gated] → scoring → reporting → finalize
```

Every stage is individually flag-gated and `finalize` aggregates whatever actually
ran, so a deployment running a subset produces a coherent `partial` job rather
than a broken one.

**Scoring and reporting need no LLM credential.** `RiskScoringEngine` is pure
computation over findings and the reporting engine is a renderer, so they run as
standalone stages rather than as byproducts of the AI stage. A default install
with no model key still produces a real risk score, per-domain decomposition, and
downloadable reports in five formats. The multi-agent stage — six agents in
parallel over manifest, permission, code, API, network, and threat-intel, see
[ai/orchestration/](ai/orchestration/) — layers narrative on top when enabled, and
is gated off by default (`SEPHELA_AI_ENABLED`) because it is the one stage that
cannot degrade without a paid credential.

Dynamic analysis is also off by default (`SEPHELA_DYNAMIC_ENABLED`); it needs the
isolated sandbox, which needs KVM.

Phase 14 covers authentication and RBAC with per-tenant isolation, an append-only
audit trail, rate limiting, Kubernetes manifests with an isolated malware-execution
pool, a signed-image delivery pipeline, a DR runbook, and a load-test harness.
Two Phase-14 items are **written but unvalidated**, because neither can be exercised
from this repository alone:

| Item | State |
|---|---|
| K8s manifests | Structure, references, and security posture are CI-checked ([37 tests](backend/tests/test_k8s_manifests.py)); never applied to a cluster. See [infra/k8s/README.md](infra/k8s/README.md) for the specific unknowns. |
| Load SLOs | Thresholds are encoded and gate a run, but are calibrated from design targets, not measurement. See [infra/load/README.md](infra/load/README.md). |
| DR RTO/RPO | Runbook complete; no game-day rehearsed, so the targets are intent rather than fact. |
| Progressive delivery | Not implemented — rollouts are `maxUnavailable: 0` rolling updates, not canary/blue-green. |
| Terraform, dashboards | Not started. |

The static → code-intel handoff of the decompiled JADX tree now goes through object
storage ([backend/app/services/artifacts.py](backend/app/services/artifacts.py)), so
it no longer depends on the two stages landing on the same worker. The local path
stays as the fast path; the archive is the fallback, and code intel deletes it as the
last consumer. It remains an optimisation — the engine treats the tree as optional,
so an oversized tree or an unreachable bucket costs call-graph and control-flow depth
rather than correctness.

| Component | Location |
|---|---|
| API / orchestration | [backend/](backend/) |
| Analysis engines | [engines/static/](engines/static/), [engines/code_intel/](engines/code_intel/), [engines/dynamic/](engines/dynamic/), [engines/threat_intel/](engines/threat_intel/) |
| GenAI, scoring, RAG | [ai/](ai/), [ai/scoring/](ai/scoring/), [ai/rag/](ai/rag/) |
| Reporting | [engines/reporting/](engines/reporting/) |
| Dashboard | [frontend/](frontend/) |

## Architecture docs
Start at [docs/architecture/00-overview.md](docs/architecture/00-overview.md).

| # | Document |
|---|---|
| 00 | [Overview, vision, principles](docs/architecture/00-overview.md) |
| 01 | [Technology stack & justification](docs/architecture/01-tech-stack.md) |
| 02 | [Microservice boundaries](docs/architecture/02-services.md) |
| 03 | [Inter-service communication & contracts](docs/architecture/03-communication.md) |
| 04 | [Object models & database schema](docs/architecture/04-data-model.md) |
| 05 | [Message queue architecture](docs/architecture/05-messaging.md) |
| 06 | [API specification](docs/architecture/06-api-spec.md) |
| 07 | [Data-flow diagrams](docs/architecture/07-data-flow.md) |
| 08 | [Deployment architecture](docs/architecture/08-deployment.md) |
| 09 | [Security considerations](docs/architecture/09-security.md) |
| 10 | [Future scalability & extensibility](docs/architecture/10-scalability.md) |
| 11 | [Development standards](docs/architecture/11-dev-standards.md) |
| 12 | [Repository structure](docs/architecture/12-repo-structure.md) |

## Roadmap
Phase 1 Architecture ✅ → 2 Backend ✅ → 3 Frontend ✅ → 4 Upload ✅ → 5 Static ✅
→ 6 Code Intel ✅ → 7 GenAI ✅ → 8 Risk Scoring ✅ → 9 Reporting ✅ → 10 Dynamic ✅
→ 11 Threat Intel ✅ → 12 RAG ✅ → 13 Multi-Agent ✅ → 14 Production Hardening ✅.

Every later phase has a reserved home in the architecture (see doc 10).

## Running it
```bash
make up               # postgres, redis, qdrant, api, worker, frontend (:3000)
make up-api           # backend only, no dashboard
make migrate          # apply DB migrations
make install-engines  # install all five analysis engines into the backend venv
make install-ai       # install the GenAI subsystem (the AI stage imports `ai`)
make test             # backend tests
make test-engines     # each engine's own suite
make test-ai          # multi-agent, GenAI, scoring, and RAG suites
```

The dashboard runs at http://localhost:3000 and proxies `/api/*` to the API
through a Next rewrite, so the browser stays same-origin and there is no CORS
configuration to get wrong. To run it outside compose: `cd frontend && npm install
&& npm run dev` (set `BACKEND_URL` if the API is not on `localhost:8000`).

Uploading an APK on a stock install — no LLM key, no sandbox — walks
`static → code_intel → threat_intel → scoring → reporting` and lands on a report
with a score, its per-domain decomposition, findings ranked by severity and each
expandable to its provenance, and downloads in JSON, Markdown, HTML, and SARIF
(PDF additionally needs `weasyprint`; without it that one format is reported as
missing rather than failing the stage).

`make install-ai` is not optional for the backend suite: `app.tasks.ai` imports the
`ai` package, so collection fails without it.

There is no self-service registration — tenants are banks, so provisioning is an
operator action. Create the first organisation and admin before logging in:

```bash
make bootstrap-admin ORG="Example Bank" EMAIL=admin@bank.example
```

## Operating it
```bash
make ci-gates      # every gate CI runs: lint, format, types, tests, security, imports
make k8s-validate  # manifest structure + security posture (no cluster needed)
make k8s-render ENV=prod
make load-read     # k6 read load — staging only
```

| Topic | Where |
|---|---|
| Deploying | [infra/k8s/README.md](infra/k8s/README.md), [infra/k8s/deploy.sh](infra/k8s/deploy.sh) |
| Backup & DR | [docs/runbooks/backup-and-dr.md](docs/runbooks/backup-and-dr.md) |
| Load testing & SLOs | [infra/load/README.md](infra/load/README.md) |
| Security controls | [docs/architecture/09-security.md](docs/architecture/09-security.md) |

Threat intel works with no API keys (URLhaus answers anonymously) and the RAG
service needs no vector database or embedding key by default — see
[.env.example](.env.example) for what each key adds.
