"""evidence + findings — engine output persistence (Phase 10 wiring)

Adds the two tables every engine stage writes into: ``evidence`` (the raw
Evidence Envelope, JSONB + GIN so the contract can evolve additively) and
``findings`` (normalized rows for dashboard filtering and risk scoring).

See docs/architecture/04-data-model.md.

Revision ID: 0002_evidence_findings
Revises: 0001_initial
Create Date: 2026-08-02
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

_TS = sa.DateTime(timezone=True)

revision: str = "0002_evidence_findings"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ---- evidence (raw engine envelopes) ----
    op.create_table(
        "evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "stage_run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("stage_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("engine_name", sa.String(64), nullable=False),
        sa.Column("envelope_version", sa.String(16), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("large_artifact_uri", sa.Text(), nullable=True),
        sa.Column("created_at", _TS, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", _TS, server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_evidence_job_id", "evidence", ["job_id"])
    op.create_index("ix_evidence_payload", "evidence", ["payload"], postgresql_using="gin")

    # ---- findings (normalized for querying/aggregation) ----
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "evidence_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("evidence.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("source_engine", sa.String(64), nullable=False),
        sa.Column("finding_id", sa.String(128), nullable=False),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("provenance", postgresql.JSONB(), nullable=True),
        sa.Column("mitre", postgresql.ARRAY(sa.Text()), nullable=False, server_default="{}"),
        sa.Column("owasp_mobile", postgresql.ARRAY(sa.Text()), nullable=False, server_default="{}"),
        sa.Column("created_at", _TS, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", _TS, server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_findings_job_id", "findings", ["job_id"])
    op.create_index("ix_findings_type", "findings", ["type"])
    op.create_unique_constraint(
        "uq_finding_job_engine_id", "findings", ["job_id", "source_engine", "finding_id"]
    )


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_index("ix_evidence_payload", table_name="evidence")
    op.drop_index("ix_evidence_job_id", table_name="evidence")
    op.drop_table("evidence")
