COMPOSE = docker compose -f infra/compose/docker-compose.yml

SANDBOX_COMPOSE = docker compose -f infra/sandbox/docker-compose.sandbox.yml

help:
	@# [0-9] included: without it, targets like `k8s-validate` are silently absent
	@# from this listing — present in the Makefile but undiscoverable.
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

up:            ## Start local full stack (postgres, redis, api, worker)
	$(COMPOSE) up --build

down:          ## Stop the stack and remove volumes
	$(COMPOSE) down -v

logs:          ## Tail service logs
	$(COMPOSE) logs -f

migrate:       ## Apply DB migrations inside the api container
	$(COMPOSE) run --rm api alembic upgrade head

revision:      ## Autogenerate a migration: make revision m="add users"
	$(COMPOSE) run --rm api alembic revision --autogenerate -m "$(m)"

install-engines: ## Install analysis engines into the backend venv (editable)
	cd backend && pip install -e ../engines/dynamic -e ../engines/threat_intel

install-ai:    ## Install the GenAI subsystem (the AI stage imports `ai`)
	pip install -e ai

bootstrap-admin: ## Create the first org + admin user: make bootstrap-admin ORG="Bank" EMAIL=a@b.c
	cd backend && python -m app.cli bootstrap "$(ORG)" "$(EMAIL)" --generate-password

test:          ## Run backend tests (needs install-ai: app.tasks.ai imports `ai`)
	cd backend && pytest

test-engines:  ## Run the analysis engines' own test suites
	cd engines/static && pytest
	cd engines/code_intel && pytest
	cd engines/dynamic && pytest
	cd engines/threat_intel && pytest
	cd engines/reporting && pytest

test-ai:       ## Run the GenAI, scoring, and RAG suites
	pytest ai/tests

rag-ingest:    ## Ingest the knowledge corpus into the configured vector store
	python -m ai.rag

sandbox-build: ## Build the isolated dynamic-analysis sandbox image (needs KVM)
	$(SANDBOX_COMPOSE) build

k8s-validate:  ## Validate the K8s manifests (structure + security posture; no cluster needed)
	cd backend && pytest tests/test_k8s_manifests.py -q

k8s-render:    ## Render one overlay to stdout: make k8s-render ENV=prod
	kustomize build infra/k8s/overlays/$(or $(ENV),dev)

load-read:     ## k6 steady-state read load (staging only — see infra/load/README.md)
	k6 run infra/load/k6/api-read.js

load-upload:   ## k6 upload soak (staging only; check AI/dynamic flags before running)
	k6 run infra/load/k6/upload-soak.js

lint:          ## Lint (backend + AI subsystem)
	cd backend && ruff check .
	cd ai && ruff check .

fmt:           ## Format (backend + AI subsystem)
	cd backend && ruff format .
	cd ai && ruff format .

fmt-check:     ## Check formatting without rewriting (CI gate)
	cd backend && ruff format --check .
	cd ai && ruff format --check .

type:          ## Type-check (backend)
	cd backend && mypy app

test-cov:      ## Run backend tests with coverage floor (80%)
	cd backend && pytest --cov=app --cov-report=term-missing --cov-fail-under=80

security-scan: ## Run bandit (static security) + pip-audit (dependency CVEs)
	cd backend && bandit -r app/ -c pyproject.toml -ll
	cd backend && pip-audit

audit:         ## Alias for security-scan
	$(MAKE) security-scan

import-lint:   ## Enforce import boundaries (engines ↛ backend, repos own DB)
	cd backend && lint-imports

contract-test: ## Run schemathesis contract tests against the OpenAPI spec
	cd backend && pytest tests/test_contracts.py -v

lint-fe:       ## Lint + type-check frontend
	cd frontend && npm run lint && npm run typecheck

fmt-fe:        ## Format frontend with Prettier
	cd frontend && npm run format

fmt-fe-check:  ## Check frontend formatting (CI gate)
	cd frontend && npm run format:check

ci-gates:      ## Run ALL CI gates locally (lint, type, test, security, import, format)
	$(MAKE) lint
	$(MAKE) fmt-check
	$(MAKE) type
	$(MAKE) test-cov
	$(MAKE) test-ai
	$(MAKE) security-scan
	$(MAKE) import-lint
	$(MAKE) lint-fe
	$(MAKE) fmt-fe-check
