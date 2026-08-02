"""Model registry — import all models here so Alembic autogenerate sees them."""

from app.db.models.analysis import (
    AnalysisJob,
    Evidence,
    Finding,
    JobStatus,
    Sample,
    StageRun,
    StageStatus,
)
from app.db.models.identity import Organization, Role, User

__all__ = [
    "AnalysisJob",
    "Evidence",
    "Finding",
    "JobStatus",
    "Organization",
    "Role",
    "Sample",
    "StageRun",
    "StageStatus",
    "User",
]
