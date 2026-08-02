"""Tests for pipeline status aggregation.

``derive_job_status`` decides what an analyst sees at the top of a job page, so
the important property is that incomplete analysis is never reported as a clean
``completed``.
"""

from __future__ import annotations

from app.db.models.analysis import JobStatus, StageRun, StageStatus
from app.tasks.pipeline import derive_job_status


def _stage(engine: str, status: StageStatus) -> StageRun:
    return StageRun(engine_name=engine, engine_version="1.0.0", status=status)


def test_no_stages_is_completed() -> None:
    """Nothing was asked of the pipeline, so nothing is outstanding."""
    assert derive_job_status([]) is JobStatus.completed


def test_all_ok_is_completed() -> None:
    stages = [_stage("dynamic", StageStatus.ok), _stage("static", StageStatus.ok)]
    assert derive_job_status(stages) is JobStatus.completed


def test_all_failed_is_failed() -> None:
    stages = [_stage("dynamic", StageStatus.failed), _stage("static", StageStatus.failed)]
    assert derive_job_status(stages) is JobStatus.failed


def test_mixed_ok_and_failed_is_partial() -> None:
    stages = [_stage("static", StageStatus.ok), _stage("dynamic", StageStatus.failed)]
    assert derive_job_status(stages) is JobStatus.partial


def test_engine_reported_partial_is_partial() -> None:
    assert derive_job_status([_stage("dynamic", StageStatus.partial)]) is JobStatus.partial


def test_only_skipped_stages_is_completed() -> None:
    """Dynamic analysis off by policy is not a degraded run."""
    assert derive_job_status([_stage("dynamic", StageStatus.skipped)]) is JobStatus.completed


def test_ok_alongside_skipped_is_partial() -> None:
    """A skipped stage means evidence is missing that could have been collected."""
    stages = [_stage("static", StageStatus.ok), _stage("dynamic", StageStatus.skipped)]
    assert derive_job_status(stages) is JobStatus.partial


def test_a_still_running_stage_is_not_reported_as_complete() -> None:
    stages = [_stage("static", StageStatus.ok), _stage("dynamic", StageStatus.running)]
    assert derive_job_status(stages) is JobStatus.partial
