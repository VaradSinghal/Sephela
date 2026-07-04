"""Trivial task proving the queue round-trips (used by readiness checks)."""

from __future__ import annotations

from app.tasks.celery_app import celery_app


@celery_app.task(name="health.ping")
def ping() -> str:
    """Return 'pong' — smoke test for broker + worker connectivity."""
    return "pong"
