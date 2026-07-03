# Contributing to Sephela

Thanks for contributing. Sephela is an enterprise malware-analysis platform for
banking security teams — it **stores and executes hostile Android APKs**, so our
standards for correctness, security, and reproducibility are high. Read this
alongside the [architecture docs](docs/architecture/00-overview.md), especially
[Development Standards](docs/architecture/11-dev-standards.md) and
[Security](docs/architecture/09-security.md).

## Before you start
- Skim the [architecture overview](docs/architecture/00-overview.md) and the doc(s)
  for the area you're touching.
- Confirm which **phase** the work belongs to (see the roadmap in the
  [README](README.md)). Don't pull future-phase logic into an earlier phase.
- For any non-trivial change, open an issue / short design note first. Significant
  decisions get an ADR under `docs/adr/`.

## Development setup
> Analysis tooling (Androguard, JADX, APKID, Frida, Android Emulator) is
> Linux/container-first. On macOS/Windows, run engine work inside Docker.

```bash
# full local stack: postgres, redis, minio, api, workers
make up            # docker-compose up (infra/compose)
make migrate       # alembic upgrade head
make test          # run the test suite
make lint          # ruff + mypy + eslint
```
Copy `.env.example` → `.env` (gitignored). **Never commit secrets.**

## Branching & commits
- Trunk-based: short-lived branches off `main`, named `type/short-desc`
  (e.g. `feat/upload-dedup`, `fix/static-manifest-parse`).
- **[Conventional Commits](https://www.conventionalcommits.org/)**:
  `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `perf:`, `ci:`.
- Squash-merge; the PR title is the squash commit and must be a valid
  Conventional Commit.

## Coding standards (summary — full list in doc 11)
- **Python 3.12**: `ruff` (lint+format), `mypy --strict`, type hints on public APIs,
  Google-style docstrings.
- **TypeScript strict**: `eslint` + `prettier`; avoid `any` without justification.
- **Thin controllers, fat services, isolated repositories** — no business logic in
  routers, no DB access outside repositories.
- **Architecture boundaries are enforced** (import-linter): engines depend only on
  `sephela_evidence` + `sephela_contracts`; no cross-service DB access; all
  cross-boundary payloads defined in `contracts/`.
- Structured JSON logs with `job_id`/`trace_id`; **never log secrets, PII, or raw
  sample strings**.

## Contracts first
Changing a cross-service payload? Update the schema in `contracts/`
(OpenAPI / AsyncAPI / JSON-Schema) **first** — clients and Pydantic models are
generated from it. Breaking changes require a new major version.

## Testing (required to merge)
- Add/adjust **unit** tests for logic; **contract** tests when touching APIs or the
  Evidence Envelope; **integration** tests (testcontainers) for DB/queue/storage.
- Analysis engines: add cases to the curated corpus with **golden Evidence
  Envelopes**; watch for score drift.
- CI gates: `lint → type → unit → contract → integration → security-scan →
  import-linter`. Green required.

## Security expectations
- Treat every APK and all decompiled/sample-derived content as **hostile input** —
  never `eval`/render it raw, never feed it to an LLM as instructions (see prompt-
  injection controls in doc 09).
- No new network egress from analysis workers without review.
- Security-sensitive paths (auth, storage, sandbox, egress) require **2 reviewers**.
- Report vulnerabilities privately to the maintainers — **do not** open a public
  issue. (Add `SECURITY.md` with the disclosure contact when the org is set up.)

## Pull requests
- Keep PRs focused and small. Fill in the PR template: what, why, phase, testing,
  security impact.
- Update docs/ADRs/contracts alongside code.
- **Definition of Done:** code + tests + docs updated, contracts valid, security
  scan clean, observability (logs/metrics/traces) in place, reviewed, and
  demoable end-to-end.

## Code of Conduct
Be respectful and constructive. (A formal `CODE_OF_CONDUCT.md` will be added with
project governance.)
