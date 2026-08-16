"""Tests for the login / refresh / me routes.

The behaviours pinned here are the ones an attacker probes: whether a wrong email
looks different from a wrong password, whether a disabled account can still refresh
its way to a fresh token, and whether failed attempts leave a trail. All three were
absent from the Phase-2 placeholder, which minted a valid token for any email.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.security import (
    REFRESH,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
)
from app.db.models.identity import Role
from app.db.session import get_db
from app.main import app

ORG = uuid.uuid4()
USER_ID = uuid.uuid4()
EMAIL = "analyst@bank.example"
PASSWORD = "correct horse battery staple"


# Hashing is deliberately slow (12 bcrypt rounds ≈ 0.25s). Computing the common
# case once keeps the suite fast without weakening the cost factor under test.
_HASHED_PASSWORD = hash_password(PASSWORD)


class FakeUser:
    def __init__(
        self,
        *,
        is_active: bool = True,
        password: str | None = PASSWORD,
        role: Role = Role.analyst,
    ) -> None:
        self.id = USER_ID
        self.email = EMAIL
        if password is None:
            self.hashed_password = None
        else:
            self.hashed_password = (
                _HASHED_PASSWORD if password == PASSWORD else hash_password(password)
            )
        self.org_id = ORG
        self.role = role
        self.is_active = is_active


class FakeSession:
    def __init__(self) -> None:
        self.commits = 0

    async def commit(self) -> None:
        self.commits += 1

    async def flush(self) -> None:
        return None

    def add(self, _obj: Any) -> None:
        return None


class FakeUserRepo:
    user: FakeUser | None = None

    def __init__(self, _session: Any) -> None:
        pass

    async def get_by_email(self, email: str) -> FakeUser | None:
        u = FakeUserRepo.user
        return u if u and u.email == email else None

    async def get_by_id(self, user_id: uuid.UUID) -> FakeUser | None:
        u = FakeUserRepo.user
        return u if u and u.id == user_id else None


class FakeAuditRepo:
    records: list[dict[str, Any]] = []

    def __init__(self, _session: Any) -> None:
        pass

    async def record(self, action: Any, **kwargs: Any) -> None:
        FakeAuditRepo.records.append({"action": getattr(action, "value", action), **kwargs})


@pytest.fixture
def client(monkeypatch):
    from app.api.v1.routers import auth as auth_router

    monkeypatch.setattr(auth_router, "UserRepository", FakeUserRepo)
    monkeypatch.setattr(auth_router, "AuditRepository", FakeAuditRepo)
    # The security module resolves /me's principal through its own repository.
    monkeypatch.setattr("app.core.security.UserRepository", FakeUserRepo)

    FakeUserRepo.user = FakeUser()
    FakeAuditRepo.records.clear()
    session = FakeSession()

    async def _fake_db():
        yield session

    app.dependency_overrides[get_db] = _fake_db
    with TestClient(app) as c:
        c.session = session  # type: ignore[attr-defined]
        yield c
    app.dependency_overrides.clear()


def _login(client: TestClient, **overrides: Any):
    payload = {"email": EMAIL, "password": PASSWORD, **overrides}
    return client.post("/api/v1/auth/login", json=payload)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


class TestLoginSuccess:
    def test_valid_credentials_return_a_token_pair(self, client) -> None:
        resp = _login(client)

        assert resp.status_code == 200
        body = resp.json()
        assert body["access_token"] and body["refresh_token"]
        assert body["token_type"] == "bearer"
        assert body["expires_in"] > 0

    def test_the_access_token_identifies_the_user_by_id(self, client) -> None:
        # Not by email: the resolver looks the principal up by primary key.
        token = _login(client).json()["access_token"]

        assert decode_token(token)["sub"] == str(USER_ID)

    def test_the_refresh_token_is_typed_as_a_refresh_token(self, client) -> None:
        token = _login(client).json()["refresh_token"]

        assert decode_token(token, expect=REFRESH)["typ"] == REFRESH

    def test_a_successful_login_is_audited(self, client) -> None:
        _login(client)

        assert "login.succeeded" in [r["action"] for r in FakeAuditRepo.records]

    def test_the_email_is_matched_case_insensitively(self, client) -> None:
        resp = _login(client, email="ANALYST@bank.example")

        assert resp.status_code == 200


class TestLoginFailure:
    def test_a_wrong_password_is_rejected(self, client) -> None:
        resp = _login(client, password="wrong")

        assert resp.status_code == 401

    def test_an_unknown_email_is_rejected(self, client) -> None:
        resp = _login(client, email="nobody@bank.example")

        assert resp.status_code == 401

    def test_unknown_email_and_wrong_password_are_indistinguishable(self, client) -> None:
        # Any difference here turns login into a user-enumeration oracle, handing an
        # attacker the list of a bank's analyst accounts.
        unknown = _login(client, email="nobody@bank.example")
        wrong_pw = _login(client, password="wrong")

        assert unknown.status_code == wrong_pw.status_code
        assert unknown.json()["detail"] == wrong_pw.json()["detail"]

    def test_a_disabled_account_is_rejected_indistinguishably(self, client) -> None:
        FakeUserRepo.user = FakeUser(is_active=False)

        disabled = _login(client)

        assert disabled.status_code == 401
        assert disabled.json()["detail"] == "Invalid email or password."

    def test_a_user_with_no_password_set_cannot_log_in(self, client) -> None:
        # An SSO-provisioned row has no local password; it must not authenticate
        # with an empty or arbitrary one.
        FakeUserRepo.user = FakeUser(password=None)

        assert _login(client).status_code == 401
        assert _login(client, password="").status_code == 401

    @pytest.mark.parametrize(
        ("email", "reason"),
        [("nobody@bank.example", "unknown_user"), (EMAIL, "bad_password")],
    )
    def test_failed_attempts_are_audited_with_a_distinguishing_reason(
        self, client, email: str, reason: str
    ) -> None:
        # The response must not distinguish these, but the trail must — that is the
        # difference between hiding information from an attacker and from the SOC.
        _login(client, email=email, password="wrong")

        failures = [r for r in FakeAuditRepo.records if r["action"] == "login.failed"]
        assert failures and failures[-1]["reason"] == reason

    def test_a_failed_attempt_is_committed_despite_the_error(self, client) -> None:
        # A rejected login rolls nothing back, so the audit row must be committed
        # explicitly or the attack leaves no trace.
        _login(client, password="wrong")

        assert client.session.commits >= 1

    def test_the_audit_row_never_contains_the_password(self, client) -> None:
        _login(client, password="hunter2")

        for record in FakeAuditRepo.records:
            assert "hunter2" not in str(record)


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------


class TestRefresh:
    def test_a_refresh_token_yields_a_new_pair(self, client) -> None:
        refresh_token = _login(client).json()["refresh_token"]

        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})

        assert resp.status_code == 200
        assert resp.json()["access_token"]
        assert resp.json()["refresh_token"]

    def test_refreshing_rotates_the_refresh_token(self, client) -> None:
        # Without rotation a stolen refresh token is valid for its full lifetime.
        original = _login(client).json()["refresh_token"]

        rotated = client.post("/api/v1/auth/refresh", json={"refresh_token": original}).json()[
            "refresh_token"
        ]

        assert rotated != original

    def test_an_access_token_cannot_be_used_to_refresh(self, client) -> None:
        access = _login(client).json()["access_token"]

        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": access})

        assert resp.status_code == 401

    def test_a_deactivated_user_cannot_refresh(self, client) -> None:
        refresh_token = _login(client).json()["refresh_token"]
        FakeUserRepo.user = FakeUser(is_active=False)

        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})

        assert resp.status_code == 401

    def test_a_refresh_for_a_deleted_user_is_rejected(self, client) -> None:
        refresh_token = _login(client).json()["refresh_token"]
        FakeUserRepo.user = None

        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})

        assert resp.status_code == 401

    def test_a_garbage_refresh_token_is_rejected(self, client) -> None:
        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": "not-a-token"})

        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# /me
# ---------------------------------------------------------------------------


class TestMe:
    def test_a_valid_token_returns_the_principal_from_the_database(self, client) -> None:
        token = _login(client).json()["access_token"]

        resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        assert resp.json() == {
            "id": str(USER_ID),
            "email": EMAIL,
            "role": Role.analyst.value,
            "org_id": str(ORG),
        }

    def test_role_claims_in_the_token_do_not_affect_the_answer(self, client) -> None:
        forged = create_access_token(str(USER_ID), claims={"role": "admin"})

        resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"})

        assert resp.json()["role"] == Role.analyst.value

    def test_no_token_is_unauthorized(self, client) -> None:
        assert client.get("/api/v1/auth/me").status_code == 401

    def test_a_refresh_token_is_not_accepted_as_a_bearer_token(self, client) -> None:
        refresh_token = create_refresh_token(str(USER_ID))

        resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {refresh_token}"})

        assert resp.status_code == 401
