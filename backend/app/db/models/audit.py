"""Append-only audit trail (Phase 14).

Non-repudiation is a compliance requirement here, not a nice-to-have: this platform
holds banks' malware samples, and "who downloaded that APK" must be answerable
months later. Two design consequences:

- **Append-only.** No ``updated_at``, no ORM relationships that could cascade a
  delete, no update path in the repository. An audit row that can be edited proves
  nothing. Enforcement belongs at the database grant level too (the app role should
  hold INSERT and SELECT but not UPDATE/DELETE on this table) — see
  docs/architecture/09-security.md.
- **Denormalised actor.** ``actor_email`` is copied in rather than joined through
  ``users``, so the trail still reads correctly after a user row is renamed or
  removed, and reading it never depends on the identity tables.

Rows are immutable and grow without bound, so the table is a partitioning
candidate by ``created_at`` (doc 08, "partition large tables").
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDMixin


class AuditAction(str, enum.Enum):
    """Actions worth reconstructing after the fact.

    Deliberately not every request — a readable trail beats an exhaustive one.
    Reads are recorded only where the data is sensitive enough that *access* is the
    event (raw evidence, sample bytes).
    """

    login_succeeded = "login.succeeded"
    login_failed = "login.failed"
    token_refreshed = "token.refreshed"
    sample_uploaded = "sample.uploaded"
    evidence_accessed = "evidence.accessed"
    job_cancelled = "job.cancelled"
    access_denied = "access.denied"


class AuditOutcome(str, enum.Enum):
    success = "success"
    failure = "failure"


class AuditLog(UUIDMixin, Base):
    """One recorded action. Written once, never modified."""

    __tablename__ = "audit_logs"

    # Declared here instead of inheriting TimestampMixin, which also brings an
    # `updated_at` that an append-only table must not have.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    # Stored as strings rather than PG enums: an audit table must accept a new
    # action name without a migration, and must never reject a write because the
    # enum is behind. Validation lives in AuditAction for callers.
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)

    # Nullable because a failed login has no authenticated actor yet — recording
    # the attempt is precisely the point.
    actor_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), nullable=True, index=True
    )

    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)  # INET6 length
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    trace_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        # The two queries an investigation actually runs: "everything this org did,
        # newest first" and "everything that touched this object".
        Index("ix_audit_logs_org_created", "org_id", "created_at"),
        Index("ix_audit_logs_target", "target_type", "target_id"),
    )
