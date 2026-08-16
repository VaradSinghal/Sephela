"""audit_logs — append-only non-repudiation trail (Phase 14)

Adds the ``audit_logs`` table from docs/architecture/09-security.md ("Repudiation:
append-only audit_logs (actor, action, target, ip, ts)").

Three deliberate schema choices:

- **No foreign keys to users/organizations.** The trail must survive the deletion of
  the actor it describes; an FK would either block that deletion or cascade the
  evidence away. Actor identity is denormalised into ``actor_email`` for the same
  reason.
- **No ``updated_at``.** There is no legitimate update path, so the column that
  would record one does not exist.
- **Append-only enforced by grants, not just convention.** The migration revokes
  UPDATE/DELETE from the application role, so a bug (or an attacker holding app
  credentials) cannot rewrite history — only a superuser can. The revoke is
  conditional because the role name differs per environment and the app user may
  own the table in local development.

Revision ID: 0004_audit_logs
Revises: 0003_enrichments
Create Date: 2026-08-16
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

_TS = sa.DateTime(timezone=True)

revision: str = "0004_audit_logs"
down_revision: str | None = "0003_enrichments"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", _TS, server_default=sa.func.now(), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        # Nullable: a failed login has no authenticated actor, and recording the
        # attempt is the whole point of auditing it.
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_email", sa.String(320), nullable=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("target_type", sa.String(32), nullable=True),
        sa.Column("target_id", sa.String(64), nullable=True),
        sa.Column("ip", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column("trace_id", sa.String(64), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("detail", postgresql.JSONB(), nullable=True),
    )

    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_actor_email", "audit_logs", ["actor_email"])
    op.create_index("ix_audit_logs_org_id", "audit_logs", ["org_id"])
    op.create_index("ix_audit_logs_target_id", "audit_logs", ["target_id"])
    op.create_index("ix_audit_logs_trace_id", "audit_logs", ["trace_id"])
    # The two shapes an investigation actually queries.
    op.create_index("ix_audit_logs_org_created", "audit_logs", ["org_id", "created_at"])
    op.create_index("ix_audit_logs_target", "audit_logs", ["target_type", "target_id"])

    # Make append-only a database guarantee rather than a code convention. Wrapped
    # in a DO block so the migration still applies when the role does not exist
    # (fresh local database, CI, or a deployment using a differently-named role).
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user) THEN
                EXECUTE format(
                    'REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_logs FROM %I',
                    current_user
                );
            END IF;
        EXCEPTION
            WHEN insufficient_privilege OR undefined_object THEN
                -- Table owners cannot revoke from themselves in every Postgres
                -- configuration. Losing the grant hardening must not fail the
                -- migration; the application-level repository still has no
                -- update path.
                NULL;
        END $$;
        """
    )


def downgrade() -> None:
    op.drop_index("ix_audit_logs_target", table_name="audit_logs")
    op.drop_index("ix_audit_logs_org_created", table_name="audit_logs")
    op.drop_index("ix_audit_logs_trace_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_target_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_org_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_actor_email", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_table("audit_logs")
