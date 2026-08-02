COMPOSE = docker compose -f infra/compose/docker-compose.yml

SANDBOX_COMPOSE = docker compose -f infra/sandbox/docker-compose.sandbox.yml

.PHONY: help up down logs migrate revision test lint fmt type shell-api \
        install-engines test-engines sandbox-build

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

up:            ## Start local full stack (postgres, redis, api, worker)
	$(COMPOSE) up --build

down:          ## Stop the stack and remove volumes
	$(COMPOSE) down -v

logs:          ## Tail service logs
	$(COMPOSE) logs -f

migrate:       ## Apply DB migrations inside the api container
	$(COMPOSE) run --rm api alembic upgrade head

revision:      ## Autogenerate a migration: make revision m="add users"
	cd backend && alembic revision --autogenerate -m "$(m)"

install-engines: ## Install analysis engines into the backend venv (editable)
	cd backend && pip install -e ../engines/dynamic

test:          ## Run backend tests
	cd backend && pytest

test-engines:  ## Run the analysis engines' own test suites
	cd engines/static && pytest
	cd engines/code_intel && pytest
	cd engines/dynamic && pytest
	cd engines/reporting && pytest

sandbox-build: ## Build the isolated dynamic-analysis sandbox image (needs KVM)
	$(SANDBOX_COMPOSE) build

lint:          ## Lint
	cd backend && ruff check .

fmt:           ## Format
	cd backend && ruff format .

type:          ## Type-check
	cd backend && mypy app
