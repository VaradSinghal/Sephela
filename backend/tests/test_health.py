"""Smoke tests for the app: it boots and liveness responds."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


def test_liveness() -> None:
    with TestClient(app) as client:
        resp = client.get("/api/v1/health/live")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_openapi_available() -> None:
    with TestClient(app) as client:
        resp = client.get("/api/v1/openapi.json")
    assert resp.status_code == 200
    assert resp.json()["info"]["title"] == "Sephela"
