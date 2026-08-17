"""Route-level tests for the report endpoints.

Three things are guarded here, none of which a unit test of the assembly code can
see:

- The tenant boundary is actually *wired* onto both routes — a report is the most
  exportable thing the platform produces, so a route that forgot ``org_id`` would
  leak another bank's analysis.
- A download is audited. The export is the moment analysis leaves the platform.
- The endpoints degrade honestly: no report yet, an unrendered format, and a
  manifest whose bytes have gone are three different 404s, not a 500.

The DB and storage are faked; what matters is which principal each route admits,
which ``org_id`` it passes down, and what it does with the rows it gets back.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.deps import storage_dep
from app.core.security import CurrentUser, get_current_user
from app.db.models.identity import Role
from app.db.session import get_db
from app.main import app

ORG = uuid.uuid4()
OTHER_ORG = uuid.uuid4()
JOB_ID = uuid.uuid4()

_MANIFEST = {
    "json": "reports/ab/job/report.json",
    "pdf": "reports/ab/job/report.pdf",
}

_REPORT_PAYLOAD: dict[str, Any] = {
    "report_id": f"rpt-{JOB_ID}",
    "status": "ok",
    "errors": [],
    "evidence": {
        "report": {"executive_summary": {"overview": "Templated.", "risk_score": 87.5}},
        "artifacts": dict(_MANIFEST),
    },
}

_SCORING_PAYLOAD: dict[str, Any] = {
    "evidence": {
        "scoring": {
            "final_score": 87.5,
            "base_score": 80.0,
            "synergy_bonus": 7.5,
            "tier": "malicious",
            "confidence": 0.9,
            "primary_category": "banking_trojan",
            "domain_scores": [
                {
                    "domain": "permissions",
                    "weight": 0.25,
                    "raw_score": 90.0,
                    "weighted_score": 22.5,
                    "finding_count": 3,
                }
            ],
            "synergy_bonuses": [
                {
                    "rule_id": "overlay+accessibility",
                    "name": "Overlay with accessibility",
                    "description": "Together these enable credential capture.",
                    "bonus": 7.5,
                }
            ],
        }
    }
}


class FakeSession:
    async def commit(self) -> None:
        return None

    async def flush(self) -> None:
        return None

    def add(self, _obj: Any) -> None:
        return None


class FakeJob:
    def __init__(self, org_id: uuid.UUID | None = ORG) -> None:
        self.id = JOB_ID
        self.org_id = org_id


class FakeJobRepo:
    """Honours the org filter, so cross-tenant reads miss exactly as in SQL."""

    instances: list[FakeJobRepo] = []

    def __init__(self, _session: Any) -> None:
        self.get_calls: list[dict[str, Any]] = []
        FakeJobRepo.instances.append(self)

    async def get(self, job_id: uuid.UUID, *, org_id: uuid.UUID | None = None) -> FakeJob | None:
        self.get_calls.append({"job_id": job_id, "org_id": org_id})
        job = FakeJob()
        if org_id is not None and job.org_id != org_id:
            return None
        return job


class FakeEvidence:
    def __init__(self, engine_name: str, payload: dict[str, Any]) -> None:
        self.engine_name = engine_name
        self.payload = payload
        self.created_at = datetime.now(UTC)


class FakeEvidenceRepo:
    rows: list[FakeEvidence] = []

    def __init__(self, _session: Any) -> None:
        pass

    async def list_for_job(self, _job_id: uuid.UUID, *, engine: str | None = None) -> list[Any]:
        if engine is None:
            return FakeEvidenceRepo.rows
        return [r for r in FakeEvidenceRepo.rows if r.engine_name == engine]


class FakeAuditRepo:
    records: list[dict[str, Any]] = []

    def __init__(self, _session: Any) -> None:
        pass

    async def record(self, action: Any, **kwargs: Any) -> None:
        FakeAuditRepo.records.append({"action": getattr(action, "value", action), **kwargs})


class FakeStorage:
    """Serves the manifest's keys; anything else is genuinely absent."""

    def __init__(self, present: dict[str, bytes] | None = None) -> None:
        if present is None:
            present = dict.fromkeys(_MANIFEST.values(), b"%PDF-")
        self.present = present
        self.loaded: list[str] = []

    async def load(self, key: str) -> bytes:
        self.loaded.append(key)
        if key not in self.present:
            raise FileNotFoundError(key)
        return self.present[key]

    async def save(self, key: str, data: bytes) -> str:  # pragma: no cover
        raise AssertionError("the read path must not write")

    async def exists(self, key: str) -> bool:  # pragma: no cover
        return key in self.present

    async def delete(self, key: str) -> None:  # pragma: no cover
        raise AssertionError("the read path must not delete")


def _principal(role: Role, org_id: uuid.UUID | None = ORG) -> CurrentUser:
    return CurrentUser(
        id=str(uuid.uuid4()),
        email=f"{role.value}@bank.example",
        role=role.value,
        org_id=str(org_id) if org_id else None,
    )


@pytest.fixture
def storage() -> FakeStorage:
    return FakeStorage()


@pytest.fixture
def client(monkeypatch, storage: FakeStorage):
    from app.api.v1.routers import reports as reports_router

    monkeypatch.setattr(reports_router, "JobRepository", FakeJobRepo)
    monkeypatch.setattr(reports_router, "EvidenceRepository", FakeEvidenceRepo)
    monkeypatch.setattr(reports_router, "AuditRepository", FakeAuditRepo)

    FakeJobRepo.instances.clear()
    FakeAuditRepo.records.clear()
    FakeEvidenceRepo.rows = [
        FakeEvidence("reporting", _REPORT_PAYLOAD),
        FakeEvidence("scoring", _SCORING_PAYLOAD),
    ]

    async def _fake_db():
        yield FakeSession()

    app.dependency_overrides[get_db] = _fake_db
    app.dependency_overrides[storage_dep] = lambda: storage

    def _as(role: Role, org_id: uuid.UUID | None = ORG) -> TestClient:
        app.dependency_overrides[get_current_user] = lambda: _principal(role, org_id)
        return TestClient(app)

    yield _as
    app.dependency_overrides.clear()
    FakeEvidenceRepo.rows = []


class TestStructuredReport:
    @pytest.mark.parametrize("role", [Role.viewer, Role.analyst, Role.admin])
    def test_any_role_can_read_the_report(self, client, role: Role) -> None:
        # Viewer-readable: the report is the triaged conclusion, not the raw
        # sample-derived content that gates /evidence behind analyst.
        resp = client(role).get(f"/api/v1/jobs/{JOB_ID}/report")

        assert resp.status_code == 200

    def test_it_returns_the_score_decomposition(self, client) -> None:
        resp = client(Role.viewer).get(f"/api/v1/jobs/{JOB_ID}/report")

        score = resp.json()["score"]
        assert score["final_score"] == 87.5
        assert score["tier"] == "malicious"
        # The decomposition is what makes the number defensible.
        assert score["domain_scores"][0]["domain"] == "permissions"
        assert score["synergy_bonuses"][0]["rule_id"] == "overlay+accessibility"

    def test_it_advertises_only_the_formats_that_were_rendered(self, client) -> None:
        resp = client(Role.viewer).get(f"/api/v1/jobs/{JOB_ID}/report")

        formats = resp.json()["formats"]
        assert sorted(formats) == ["json", "pdf"]
        assert formats["pdf"] == f"/api/v1/jobs/{JOB_ID}/report/pdf"

    def test_a_report_without_scoring_still_reads(self, client) -> None:
        # Only the reporting stage ran — e.g. no findings to score.
        FakeEvidenceRepo.rows = [FakeEvidence("reporting", _REPORT_PAYLOAD)]

        resp = client(Role.viewer).get(f"/api/v1/jobs/{JOB_ID}/report")

        assert resp.status_code == 200
        assert resp.json()["score"] is None

    def test_no_report_yet_is_a_404_with_an_explanation(self, client) -> None:
        FakeEvidenceRepo.rows = []

        resp = client(Role.viewer).get(f"/api/v1/jobs/{JOB_ID}/report")

        assert resp.status_code == 404
        assert "reporting stage" in resp.json()["detail"]

    def test_renderer_warnings_are_surfaced(self, client) -> None:
        # A partial report must explain its own gap rather than look complete.
        FakeEvidenceRepo.rows = [
            FakeEvidence(
                "reporting",
                {
                    **_REPORT_PAYLOAD,
                    "errors": [{"extractor": "renderer", "message": "Formats not rendered: pdf"}],
                },
            )
        ]

        resp = client(Role.viewer).get(f"/api/v1/jobs/{JOB_ID}/report")

        assert resp.json()["warnings"] == ["Formats not rendered: pdf"]


class TestDownload:
    def test_it_streams_the_artifact_with_the_right_type(self, client, storage) -> None:
        resp = client(Role.viewer).get(f"/api/v1/jobs/{JOB_ID}/report/pdf")

        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert "attachment" in resp.headers["content-disposition"]
        assert str(JOB_ID) in resp.headers["content-disposition"]
        assert storage.loaded == [_MANIFEST["pdf"]]

    def test_a_download_is_audited(self, client) -> None:
        client(Role.viewer).get(f"/api/v1/jobs/{JOB_ID}/report/pdf")

        actions = [r["action"] for r in FakeAuditRepo.records]
        assert "report.downloaded" in actions
        record = next(r for r in FakeAuditRepo.records if r["action"] == "report.downloaded")
        assert record["target_id"] == str(JOB_ID)
        assert record["detail"]["format"] == "pdf"

    def test_an_unrendered_format_is_a_404_that_lists_what_exists(self, client) -> None:
        resp = client(Role.viewer).get(f"/api/v1/jobs/{JOB_ID}/report/sarif")

        assert resp.status_code == 404
        assert "json, pdf" in resp.json()["detail"]

    def test_reading_is_not_audited_as_a_download(self, client) -> None:
        # Only the export leaves the platform; in-app reads are not the event.
        client(Role.viewer).get(f"/api/v1/jobs/{JOB_ID}/report")

        assert FakeAuditRepo.records == []

    def test_a_manifest_whose_bytes_are_gone_is_a_404_not_a_500(self, client, monkeypatch) -> None:
        # Retention or a wiped volume: the row promises an artifact storage no
        # longer has.
        empty = FakeStorage(present={})
        app.dependency_overrides[storage_dep] = lambda: empty

        resp = client(Role.viewer).get(f"/api/v1/jobs/{JOB_ID}/report/pdf")

        assert resp.status_code == 404
        assert "no longer available" in resp.json()["detail"]


class TestTenantBoundary:
    def test_another_orgs_report_is_not_found_rather_than_forbidden(self, client) -> None:
        # Confirming the job exists is itself a disclosure.
        resp = client(Role.analyst, OTHER_ORG).get(f"/api/v1/jobs/{JOB_ID}/report")

        assert resp.status_code == 404

    def test_another_orgs_download_is_not_found(self, client) -> None:
        resp = client(Role.analyst, OTHER_ORG).get(f"/api/v1/jobs/{JOB_ID}/report/pdf")

        assert resp.status_code == 404

    def test_both_report_routes_pass_an_org_scope(self, client) -> None:
        # A route that forgets the scope reads across tenants, so assert neither does.
        c = client(Role.analyst)
        for path in (
            f"/api/v1/jobs/{JOB_ID}/report",
            f"/api/v1/jobs/{JOB_ID}/report/pdf",
        ):
            c.get(path)

        scoped = [call["org_id"] for repo in FakeJobRepo.instances for call in repo.get_calls]
        assert len(scoped) == 2, "both routes must look the job up"
        assert all(org == ORG for org in scoped)

    def test_the_download_route_checks_the_tenant_before_reading_storage(
        self, client, storage
    ) -> None:
        client(Role.analyst, OTHER_ORG).get(f"/api/v1/jobs/{JOB_ID}/report/pdf")

        assert storage.loaded == []


class TestAuthenticationIsRequired:
    @pytest.mark.parametrize("suffix", ["", "/pdf"])
    def test_an_unauthenticated_request_is_rejected(self, suffix: str) -> None:
        app.dependency_overrides.clear()
        with TestClient(app) as anon:
            resp = anon.get(f"/api/v1/jobs/{JOB_ID}/report{suffix}")

        assert resp.status_code == 401
