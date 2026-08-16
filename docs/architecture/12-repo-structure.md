# Repository Structure

A **polyrepo-friendly monorepo**: one repo, clear service roots, independent build
& deploy per service. Shared contracts live in versioned packages so services
never import each other's internals.

```
sephela/
├── docs/
│   └── architecture/              # this design set (Phase 1)
├── contracts/                     # SINGLE SOURCE OF TRUTH for cross-service types
│   ├── openapi/                   # REST API specs (yaml)
│   ├── asyncapi/                  # queue message/event schemas
│   ├── json-schema/               # evidence & report schemas (engine outputs)
│   └── proto/                     # (future) gRPC for engine RPC
│
├── frontend/                      # Next.js dashboard  (Phase 3)
│   ├── src/
│   │   ├── app/                   # App Router: routes/pages
│   │   │   ├── (auth)/            #   login, forgot-password
│   │   │   ├── (dashboard)/       #   dashboard, uploads, reports, tasks
│   │   ├── components/            # ui/ (primitives), features/ (domain)
│   │   ├── lib/api/               # typed API client (generated from openapi)
│   │   ├── lib/state/             # state mgmt (server: React Query; client: Zustand)
│   │   ├── hooks/                 # reusable hooks
│   │   └── styles/                # Tailwind config, tokens
│   ├── public/
│   └── tests/                     # unit (vitest) + e2e (playwright)
│
├── backend/                       # FastAPI API gateway + core services (Phase 2)
│   ├── app/
│   │   ├── api/v1/                # routers (auth, uploads, jobs, reports, health)
│   │   ├── core/                  # config, logging, security, exceptions, middleware
│   │   ├── db/                    # SQLAlchemy models, session, base
│   │   ├── schemas/               # Pydantic request/response models
│   │   ├── services/              # business logic (thin controllers, fat services)
│   │   ├── repositories/          # data-access layer (persistence abstraction)
│   │   ├── storage/               # object-storage abstraction (S3/MinIO/local)
│   │   ├── events/                # queue producers, event publishing
│   │   └── main.py
│   ├── alembic/                   # migrations
│   ├── tests/
│   └── pyproject.toml
│
├── workers/                       # Celery workers — orchestration & pipeline (Phase 2,4)
│   ├── app/
│   │   ├── tasks/                 # celery task definitions (thin)
│   │   ├── pipeline/              # analysis orchestration (DAG of stages)
│   │   ├── engines_client/        # clients to call engine modules
│   │   └── celeryconfig.py
│   └── tests/
│
├── engines/                       # analysis engines — each independently deployable
│   ├── static/                    # Static Analysis Engine        (Phase 5)
│   │   ├── extractors/            #   manifest, permissions, certs, strings,
│   │   │                          #   urls_ips, decompile, obfuscation, packers...
│   │   ├── pipeline.py            #   runs extractors, emits evidence JSON
│   │   └── tests/
│   ├── code_intel/                # Code Intelligence Engine       (Phase 6)
│   ├── dynamic/                   # Dynamic Analysis Engine        (Phase 10)
│   │   ├── sandbox/               #   emulator control
│   │   ├── frida/ mitmproxy/      #   instrumentation, capture
│   │   └── normalizer/            #   → normalized runtime events
│   ├── threat_intel/              # Threat Intelligence Engine     (Phase 11)
│   │   └── providers/             #   virustotal, otx, abuseipdb, urlhaus, bazaar
│   └── signatures/                # signature/YARA/APKID malware engines (Phase 5+)
│
├── ai/                            # GenAI subsystem                (Phase 7,12,13)
│   ├── orchestration/             # LangGraph graph, orchestrator agent
│   ├── agents/                    # specialized agents (manifest, permission, code…)
│   ├── prompts/                   # versioned, modular prompt templates
│   ├── schemas/                   # structured-output schemas (Pydantic)
│   ├── rag/                       # vector store client, retrievers, ingestion
│   ├── scoring/                   # Risk Scoring Engine            (Phase 8)
│   └── validation/                # JSON/structured-output validators
│
├── reporting/                     # Reporting Engine               (Phase 9)
│   ├── renderers/                 # json, markdown, pdf
│   └── templates/
│
├── libs/                          # shared internal python libs (versioned)
│   ├── sephela_contracts/         # generated pydantic models from /contracts
│   ├── sephela_common/            # logging, tracing, errors, ids, feature flags
│   └── sephela_evidence/          # evidence envelope models + helpers
│
├── infra/                         # infrastructure as code        (Phase 14 ✅)
│   ├── compose/                   # docker-compose.yml (local full stack)
│   ├── sandbox/                   # isolated dynamic-analysis image + scripts
│   ├── k8s/                       # kustomize manifests               ✅
│   │   ├── base/                  #   prod-shaped, no image digest
│   │   ├── overlays/{dev,staging,prod}/   # pin the digest, adjust scale
│   │   ├── deploy.sh              #   verify → render → migrate → apply → wait
│   │   └── README.md              #   what is verified vs needs a cluster
│   ├── load/                      # k6 scenarios + the SLOs they gate   ✅
│   ├── terraform/                 # cloud infra (network, storage)  — not started
│   └── observability/             # dashboards, alert rules         — not started
│
├── .github/workflows/             # CI/CD pipelines
├── Makefile                       # dev ergonomics (lint, test, up, migrate)
└── README.md
```

## Why this layout

- **`contracts/` as source of truth.** OpenAPI, AsyncAPI and JSON-Schema define
  every cross-boundary payload. Client SDKs and Pydantic models are *generated*,
  eliminating drift between frontend, backend, workers, and engines.
- **Engines are leaves, not hubs.** They depend only on `sephela_evidence` +
  `sephela_contracts`. They never import backend/worker code, so any engine can be
  extracted into its own repo/service later with zero refactor.
- **`ai/` isolated from `backend/`.** LLM concerns (prompts, agents, RAG) evolve on
  a different cadence and have different scaling/cost profiles; keeping them
  separate lets phase 7/13 iterate without destabilizing the API.
- **`libs/` prevents copy-paste.** Cross-cutting concerns (IDs, logging, evidence
  envelope) are versioned packages, not duplicated code.
