"""analysis_jobs.risk_score / risk_tier — denormalised scoring result

The scoring stage writes its full ``ScoringResult`` (per-domain breakdown, synergy
rules, confidence) into ``evidence`` like every other engine. These two columns
are a denormalised copy of just the headline numbers, so listing or ranking jobs
by risk is a plain indexed query instead of a join into a JSONB column.

Two deliberate choices:

- **Nullable, not defaulted.** A job that has not been scored yet, and a job whose
  findings genuinely score zero, are different states. A ``NOT NULL DEFAULT 0``
  would render an unscored job as benign in every list view.
- **Index on ``risk_tier`` only.** The tier is what dashboards filter by
  ("show me everything malicious"); the score is read per-row once the tier has
  already narrowed the set, so an index on it would cost writes for nothing.

Revision ID: 0005_job_risk_score
Revises: 0004_audit_logs
Create Date: 2026-08-17
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0005_job_risk_score"
down_revision: str | None = "0004_audit_logs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("analysis_jobs", sa.Column("risk_score", sa.Float(), nullable=True))
    op.add_column("analysis_jobs", sa.Column("risk_tier", sa.String(16), nullable=True))
    op.create_index("ix_analysis_jobs_risk_tier", "analysis_jobs", ["risk_tier"])


def downgrade() -> None:
    op.drop_index("ix_analysis_jobs_risk_tier", table_name="analysis_jobs")
    op.drop_column("analysis_jobs", "risk_tier")
    op.drop_column("analysis_jobs", "risk_score")
