"""Tests for the audit trail's write path and its append-only guarantees.

An audit trail is only worth having if it cannot be edited, cannot be turned into a
credential store, and cannot break the action it records. Each of those is a test
below rather than a comment in the repository.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.db.models.audit import AuditAction, AuditLog, AuditOutcome
from app.repositories.audit import AuditRepository, _scrub


class FakeSession:
    """Captures added rows; can be told to fail on flush."""

    def __init__(self, *, fail: bool = False) -> None:
        self.added: list[Any] = []
        self.fail = fail
        self.flushes = 0

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        self.flushes += 1
        if self.fail:
            raise RuntimeError("audit table is unavailable")


class TestRecord:
    async def test_a_row_carries_the_actor_action_and_target(self) -> None:
        session = FakeSession()
        actor, org = uuid.uuid4(), uuid.uuid4()

        entry = await AuditRepository(session).record(
            AuditAction.evidence_accessed,
            actor_id=actor,
            actor_email="analyst@bank.example",
            org_id=org,
            target_type="job",
            target_id="job-1",
            ip="10.0.0.7",
        )

        assert entry is not None
        assert entry.action == "evidence.accessed"
        assert entry.outcome == AuditOutcome.success.value
        assert entry.actor_id == actor
        assert entry.actor_email == "analyst@bank.example"
        assert entry.org_id == org
        assert entry.target_id == "job-1"
        assert entry.ip == "10.0.0.7"

    async def test_the_row_is_flushed_into_the_callers_transaction(self) -> None:
        # Flushed, not committed: a rolled-back action must not leave a trail
        # claiming it happened.
        session = FakeSession()

        await AuditRepository(session).record(AuditAction.login_succeeded)

        assert session.flushes == 1
        assert len(session.added) == 1

    async def test_a_failed_login_can_be_recorded_without_an_actor(self) -> None:
        # Recording the attempt is the entire point, and there is no principal yet.
        session = FakeSession()

        entry = await AuditRepository(session).record(
            AuditAction.login_failed,
            outcome=AuditOutcome.failure,
            actor_email="attacker@example.com",
            reason="unknown_user",
        )

        assert entry is not None
        assert entry.actor_id is None
        assert entry.outcome == "failure"
        assert entry.reason == "unknown_user"

    async def test_an_audit_failure_does_not_break_the_audited_action(self) -> None:
        # An audit-table outage should degrade observability, not reject a bank's
        # upload. The caller gets None and the failure is logged.
        session = FakeSession(fail=True)

        result = await AuditRepository(session).record(AuditAction.sample_uploaded)

        assert result is None

    async def test_a_long_user_agent_is_truncated_to_the_column_width(self) -> None:
        session = FakeSession()

        entry = await AuditRepository(session).record(
            AuditAction.login_succeeded, user_agent="U" * 900
        )

        assert entry is not None
        assert len(entry.user_agent or "") == 512

    async def test_a_plain_string_action_is_accepted(self) -> None:
        # The column is a string precisely so a new action name does not need a
        # migration or an enum bump before it can be recorded.
        session = FakeSession()

        entry = await AuditRepository(session).record("custom.action")

        assert entry is not None
        assert entry.action == "custom.action"


class TestSecretScrubbing:
    def test_credential_keys_are_redacted(self) -> None:
        # The trail is broadly readable by design (compliance, investigations), so
        # it is the last place a credential should come to rest.
        scrubbed = _scrub(
            {"password": "hunter2", "token": "abc", "api_key": "k", "filename": "x.apk"}
        )

        assert scrubbed == {
            "password": "[redacted]",
            "token": "[redacted]",
            "api_key": "[redacted]",
            "filename": "x.apk",
        }

    def test_redaction_is_case_insensitive(self) -> None:
        assert _scrub({"Password": "x", "ACCESS_TOKEN": "y"}) == {
            "Password": "[redacted]",
            "ACCESS_TOKEN": "[redacted]",
        }

    def test_an_empty_detail_stays_null(self) -> None:
        assert _scrub(None) is None
        assert _scrub({}) is None

    async def test_scrubbing_is_applied_on_the_write_path(self) -> None:
        session = FakeSession()

        entry = await AuditRepository(session).record(
            AuditAction.login_failed, detail={"password": "hunter2"}
        )

        assert entry is not None
        assert entry.detail == {"password": "[redacted]"}


class TestAppendOnly:
    def test_the_repository_exposes_no_mutation_path(self) -> None:
        # A repository with an update method is an invitation to launder the trail.
        for forbidden in ("update", "delete", "edit", "purge", "remove"):
            assert not hasattr(AuditRepository, forbidden)

    def test_the_model_has_no_updated_at_column(self) -> None:
        # There is no legitimate update, so the column that would record one should
        # not exist — its presence would imply rows change.
        assert "updated_at" not in AuditLog.__table__.columns

    def test_the_model_has_no_relationships_that_could_cascade(self) -> None:
        # An FK to users would either block deleting an actor or cascade the
        # evidence away with them.
        assert not list(AuditLog.__mapper__.relationships)
        assert not list(AuditLog.__table__.foreign_keys)

    def test_the_actor_email_is_denormalised_onto_the_row(self) -> None:
        # So the trail still reads correctly after the user row is gone.
        assert "actor_email" in AuditLog.__table__.columns
