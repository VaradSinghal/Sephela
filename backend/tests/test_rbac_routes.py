"""Route-level authorization tests: role gates and the tenant boundary.

Unit tests prove ``require_role`` and the repository's ``org_id`` filter behave.
These prove they are actually *wired* onto the endpoints — the failure mode being
guarded against is a correct guard that nobody applied, which no unit test can see.

The DB is faked: what matters here is which principal each route admits and which
``org_id`` it passes down, not what Postgres returns.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.security import CurrentUser, get_current_user
from app.db.models.analysis import JobStatus
from app.db.models.identity import Role
from app.db.session import get_db
from app.main import app

ORG = uuid.uuid4()
OTHER_ORG = uuid.uuid4()
JOB_ID = uuid.uuid4()


class FakeSession:
    """Enough AsyncSession surface for routes that only commit."""

    async def commit(self) -> None:
        return None

    async def flush(self) -> None:
        return None

    def add(self, _obj: Any) -> None:
        return None


class FakeJob:
    def __init__(self, org_id: uuid.UUID | None = ORG, status: JobStatus = JobStatus.queued):
        self.id = JOB_ID
        self.sample_id = uuid.uuid4()
        self.org_id = org_id
        self.status = status
        self.progress = 0
        self.pipeline_version = "1.0.0"
        self.stages: list[Any] = []
        self.error = None
        self.created_at = datetime.now(UTC)
        self.completed_at = None
        # Null until the scoring stage runs, which is the state these RBAC tests
        # exercise — an unscored job must still serialise.
        self.risk_score = None
        self.risk_tier = None


class FakeJobRepo:
    """Honours the org filter, so cross-tenant reads miss exactly as in SQL."""

    instances: list[FakeJobRepo] = []

    def __init__(self, _session: Any) -> None:
        self.get_calls: list[dict[str, Any]] = []
        self.list_calls: list[dict[str, Any]] = []
        FakeJobRepo.instances.append(self)

    async def get(self, job_id: uuid.UUID, *, org_id: uuid.UUID | None = None) -> FakeJob | None:
        self.get_calls.append({"job_id": job_id, "org_id": org_id})
        job = FakeJob()
        if org_id is not None and job.org_id != org_id:
            return None
        return job

    async def list(self, **kwargs: Any) -> list[FakeJob]:
        self.list_calls.append(kwargs)
        return [FakeJob()]


class FakeEvidenceRepo:
    def __init__(self, _session: Any) -> None:
        pass

    async def list_for_job(self, _job_id: uuid.UUID, engine: str | None = None) -> list[Any]:
        return []


class FakeFindingRepo:
    def __init__(self, _session: Any) -> None:
        pass

    async def list_for_job(self, _job_id: uuid.UUID, **_kwargs: Any) -> list[Any]:
        return []


class FakeAuditRepo:
    """Captures audit writes so tests can assert sensitive access is recorded."""

    records: list[dict[str, Any]] = []

    def __init__(self, _session: Any) -> None:
        pass

    async def record(self, action: Any, **kwargs: Any) -> None:
        FakeAuditRepo.records.append({"action": getattr(action, "value", action), **kwargs})


def _principal(role: Role, org_id: uuid.UUID | None = ORG) -> CurrentUser:
    return CurrentUser(
        id=str(uuid.uuid4()),
        email=f"{role.value}@bank.example",
        role=role.value,
        org_id=str(org_id) if org_id else None,
    )


@pytest.fixture
def client(monkeypatch):
    """A TestClient whose principal the test chooses, with fakes for persistence."""
    from app.api.v1.routers import jobs as jobs_router
    from app.api.v1.routers import uploads as uploads_router

    monkeypatch.setattr(jobs_router, "JobRepository", FakeJobRepo)
    monkeypatch.setattr(jobs_router, "EvidenceRepository", FakeEvidenceRepo)
    monkeypatch.setattr(jobs_router, "FindingRepository", FakeFindingRepo)
    monkeypatch.setattr(jobs_router, "AuditRepository", FakeAuditRepo)
    monkeypatch.setattr(uploads_router, "AuditRepository", FakeAuditRepo)

    FakeJobRepo.instances.clear()
    FakeAuditRepo.records.clear()

    async def _fake_db():
        yield FakeSession()

    app.dependency_overrides[get_db] = _fake_db

    def _as(role: Role, org_id: uuid.UUID | None = ORG) -> TestClient:
        app.dependency_overrides[get_current_user] = lambda: _principal(role, org_id)
        # Rate limiting keys off the Authorization header and would otherwise reach
        # Redis; it fails open, but skip it so these tests stay hermetic.
        return TestClient(app)

    yield _as
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Role gates
# ---------------------------------------------------------------------------


class TestReadAccess:
    @pytest.mark.parametrize("role", [Role.viewer, Role.analyst, Role.admin])
    def test_any_role_can_read_job_status(self, client, role: Role) -> None:
        resp = client(role).get(f"/api/v1/jobs/{JOB_ID}")
        assert resp.status_code == 200

    @pytest.mark.parametrize("role", [Role.viewer, Role.analyst, Role.admin])
    def test_any_role_can_read_findings(self, client, role: Role) -> None:
        # Findings are triaged conclusions, not raw sample content.
        resp = client(role).get(f"/api/v1/jobs/{JOB_ID}/findings")
        assert resp.status_code == 200


class TestEvidenceIsAnalystGated:
    def test_a_viewer_cannot_read_raw_evidence(self, client) -> None:
        # Envelopes carry decompiled strings and captured traffic from live malware.
        resp = client(Role.viewer).get(f"/api/v1/jobs/{JOB_ID}/evidence")
        assert resp.status_code == 403

    @pytest.mark.parametrize("role", [Role.analyst, Role.admin])
    def test_analyst_and_above_can_read_raw_evidence(self, client, role: Role) -> None:
        resp = client(role).get(f"/api/v1/jobs/{JOB_ID}/evidence")
        assert resp.status_code == 200

    def test_reading_evidence_is_audited(self, client) -> None:
        client(Role.analyst).get(f"/api/v1/jobs/{JOB_ID}/evidence")

        actions = [r["action"] for r in FakeAuditRepo.records]
        assert "evidence.accessed" in actions

    def test_a_denied_read_writes_no_audit_row_for_success(self, client) -> None:
        client(Role.viewer).get(f"/api/v1/jobs/{JOB_ID}/evidence")

        assert "evidence.accessed" not in [r["action"] for r in FakeAuditRepo.records]


class TestStateChangesAreAnalystGated:
    def test_a_viewer_cannot_cancel_a_job(self, client) -> None:
        resp = client(Role.viewer).post(f"/api/v1/jobs/{JOB_ID}/cancel")
        assert resp.status_code == 403

    def test_an_analyst_can_cancel_a_job(self, client) -> None:
        resp = client(Role.analyst).post(f"/api/v1/jobs/{JOB_ID}/cancel")
        assert resp.status_code == 200

    def test_cancelling_is_audited(self, client) -> None:
        client(Role.analyst).post(f"/api/v1/jobs/{JOB_ID}/cancel")

        assert "job.cancelled" in [r["action"] for r in FakeAuditRepo.records]

    def test_a_viewer_cannot_upload(self, client) -> None:
        # Uploading is what causes malware to be executed in the sandbox.
        apk = ("x.apk", b"PK\x03\x04", "application/vnd.android.package-archive")

        resp = client(Role.viewer).post("/api/v1/uploads", files={"file": apk})

        assert resp.status_code == 403


class TestAuditTrailIsAdminOnly:
    @pytest.mark.parametrize("role", [Role.viewer, Role.analyst])
    def test_non_admins_cannot_read_the_audit_trail(self, client, role: Role) -> None:
        resp = client(role).get("/api/v1/auth/audit")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


class TestTenantBoundary:
    def test_a_job_lookup_is_scoped_to_the_callers_org(self, client) -> None:
        client(Role.analyst).get(f"/api/v1/jobs/{JOB_ID}")

        assert FakeJobRepo.instances[-1].get_calls[-1]["org_id"] == ORG

    def test_listing_jobs_is_scoped_to_the_callers_org(self, client) -> None:
        client(Role.viewer).get("/api/v1/jobs")

        assert FakeJobRepo.instances[-1].list_calls[-1]["org_id"] == ORG

    def test_another_orgs_job_reads_as_absent_not_forbidden(self, client) -> None:
        # 403 would confirm the job exists to someone outside the tenant.
        resp = client(Role.analyst, OTHER_ORG).get(f"/api/v1/jobs/{JOB_ID}")

        assert resp.status_code == 404

    def test_another_orgs_evidence_is_unreachable(self, client) -> None:
        resp = client(Role.analyst, OTHER_ORG).get(f"/api/v1/jobs/{JOB_ID}/evidence")

        assert resp.status_code == 404

    def test_another_orgs_job_cannot_be_cancelled(self, client) -> None:
        resp = client(Role.analyst, OTHER_ORG).post(f"/api/v1/jobs/{JOB_ID}/cancel")

        assert resp.status_code == 404

    def test_every_job_route_passes_an_org_scope(self, client) -> None:
        # A route that forgets the scope reads across tenants, so assert none does.
        c = client(Role.analyst)
        for path in (
            f"/api/v1/jobs/{JOB_ID}",
            f"/api/v1/jobs/{JOB_ID}/stages",
            f"/api/v1/jobs/{JOB_ID}/evidence",
            f"/api/v1/jobs/{JOB_ID}/findings",
        ):
            c.get(path)

        scoped = [call["org_id"] for repo in FakeJobRepo.instances for call in repo.get_calls]
        assert scoped, "no job lookups were recorded"
        assert all(org == ORG for org in scoped)


class TestAuthenticationIsRequired:
    def test_an_unauthenticated_request_is_rejected(self) -> None:
        # No dependency override here: the real get_current_user runs and finds no
        # bearer token.
        app.dependency_overrides.clear()
        with TestClient(app) as anon:
            resp = anon.get(f"/api/v1/jobs/{JOB_ID}")

        assert resp.status_code == 401
