"""enrichments — threat-intel verdicts + cross-job lookup cache (Phase 11)

Adds the ``enrichments`` table reserved in docs/architecture/04-data-model.md.
It doubles as the threat-intel engine's cache, so the indexes are shaped around
the cache read path — ``(ioc_type, ioc_value, provider, expires_at)`` — rather
than around ``job_id`` alone.

``job_id`` is nullable with ``ON DELETE SET NULL``: a cached verdict must outlive
the job that fetched it, and deleting one job must not evict the cache for every
other tenant.

Revision ID: 0003_enrichments
Revises: 0002_evidence_findings
Create Date: 2026-08-09
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

_TS = sa.DateTime(timezone=True)

revision: str = "0003_enrichments"
down_revision: str | None = "0002_evidence_findings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "enrichments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("ioc_type", sa.String(16), nullable=False),
        sa.Column("ioc_value", sa.Text(), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("verdict", sa.String(16), nullable=True),
        sa.Column("raw", postgresql.JSONB(), nullable=True),
        sa.Column("fetched_at", _TS, server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", _TS, nullable=True),
        sa.Column("created_at", _TS, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", _TS, server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_enrich_ioc", "enrichments", ["ioc_type", "ioc_value"])
    # Covers the cache lookup: one indicator, one provider, still fresh.
    op.create_index(
        "ix_enrich_cache",
        "enrichments",
        ["ioc_type", "ioc_value", "provider", "expires_at"],
    )
    op.create_index("ix_enrich_job_id", "enrichments", ["job_id"])


def downgrade() -> None:
    op.drop_index("ix_enrich_job_id", table_name="enrichments")
    op.drop_index("ix_enrich_cache", table_name="enrichments")
    op.drop_index("ix_enrich_ioc", table_name="enrichments")
    op.drop_table("enrichments")
