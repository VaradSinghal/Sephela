COMPOSE = docker compose -f infra/compose/docker-compose.yml

.PHONY: help up down logs migrate revision test lint fmt type shell-api

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

test:          ## Run backend tests
	cd backend && pytest

lint:          ## Lint
	cd backend && ruff check .

fmt:           ## Format
	cd backend && ruff format .

type:          ## Type-check
	cd backend && mypy app
