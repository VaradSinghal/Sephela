"""initial schema — identity + analysis (Phase 2 + Phase 4)

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ---- Enums ----
    user_role = postgresql.ENUM("admin", "analyst", "viewer", name="user_role")
    job_status = postgresql.ENUM(
        "queued", "running", "partial", "completed", "failed", "cancelled", name="job_status"
    )
    stage_status = postgresql.ENUM(
        "pending", "running", "ok", "partial", "failed", "skipped", name="stage_status"
    )

    # ---- organizations ----
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )

    # ---- users ----
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=True),
        sa.Column("role", user_role, nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_users_org_id", "users", ["org_id"])
    op.create_unique_constraint("uq_users_email", "users", ["email"])
    op.create_index("ix_users_email", "users", ["email"])

    # ---- samples ----
    op.create_table(
        "samples",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("sha1", sa.String(40), nullable=True),
        sa.Column("md5", sa.String(32), nullable=True),
        sa.Column("file_size", sa.BigInteger(), nullable=False),
        sa.Column("original_filename", sa.String(512), nullable=True),
        sa.Column("package_name", sa.String(255), nullable=True),
        sa.Column("storage_uri", sa.Text(), nullable=False),
        sa.Column(
            "created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_unique_constraint("uq_samples_sha256", "samples", ["sha256"])
    op.create_index("ix_samples_sha256", "samples", ["sha256"])
    op.create_index("ix_samples_package_name", "samples", ["package_name"])

    # ---- analysis_jobs ----
    op.create_table(
        "analysis_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "sample_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("samples.id"), nullable=False
        ),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id"),
            nullable=True,
        ),
        sa.Column(
            "requested_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True
        ),
        sa.Column("status", job_status, nullable=False, server_default="queued"),
        sa.Column("pipeline_version", sa.String(32), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_analysis_jobs_sample_id", "analysis_jobs", ["sample_id"])
    op.create_index("ix_analysis_jobs_org_id", "analysis_jobs", ["org_id"])
    op.create_index("ix_analysis_jobs_status", "analysis_jobs", ["status"])

    # ---- stage_runs ----
    op.create_table(
        "stage_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("engine_name", sa.String(64), nullable=False),
        sa.Column("engine_version", sa.String(32), nullable=False),
        sa.Column("status", stage_status, nullable=False, server_default="pending"),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_unique_constraint("uq_stage_job_engine", "stage_runs", ["job_id", "engine_name"])


def downgrade() -> None:
    op.drop_table("stage_runs")
    op.drop_table("analysis_jobs")
    op.drop_table("samples")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
    op.drop_table("organizations")
    for name in ("stage_status", "job_status", "user_role"):
        op.execute(f"DROP TYPE IF EXISTS {name}")
