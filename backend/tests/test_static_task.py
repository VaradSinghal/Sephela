"""Tests for the static and code-intel stages' failure policy.

Static evidence is the input to code intel, scoring, and reporting, so a failure
here degrades everything downstream — which makes it exactly the stage that must
not crash the job. These tests pin the mapping from each failure mode onto a stage
status, using fakes for the engines and the DB-backed StageRunner.

The code-intel tests also pin the static → code-intel handoff, including the case
that bites in production: the decompiled tree the static stage reported is not on
this worker's disk.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.db.models.analysis import Sample, StageStatus
from app.services.stages import StageOutcome
from app.tasks import code_intel as ci
from app.tasks import static as st


class FakeStageRunner:
    """Records which terminal method the task chose."""

    def __init__(self, engine: str = "static") -> None:
        self.engine = engine
        self.engine_version = "1.0.0"
        self.calls: list[str] = []
        self.payload: dict[str, Any] | None = None
        self.reason: str | None = None
        self.progress: int | None = None

    async def begin(self) -> str:
        self.calls.append("begin")
        return "stage-1"

    async def complete(self, payload: dict[str, Any], **_: Any) -> StageOutcome:
        self.calls.append("complete")
        self.payload = payload
        return StageOutcome(engine=self.engine, status=StageStatus.ok, findings=1)

    async def fail(self, exc: BaseException | str) -> StageOutcome:
        self.calls.append("fail")
        self.reason = str(exc)
        return StageOutcome(engine=self.engine, status=StageStatus.failed, error=str(exc))

    async def skip(self, reason: str) -> StageOutcome:
        self.calls.append("skip")
        self.reason = reason
        return StageOutcome(engine=self.engine, status=StageStatus.skipped, error=reason)

    async def set_progress(self, progress: int) -> None:
        self.progress = progress


class FakeEnvelope:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def model_dump(self, **_: Any) -> dict[str, Any]:
        return self._payload


class FakeStaticEngine:
    """Stands in for sephela_static; ``analyze`` is sync, as the real one is."""

    def __init__(self, payload: dict[str, Any] | None = None, exc: Exception | None = None) -> None:
        self.payload = payload or {"envelope_version": "1.0", "status": "ok", "findings": []}
        self.exc = exc
        self.seen: Path | None = None

    def analyze(self, apk_path: Any, *, job_id: str | None = None) -> FakeEnvelope:
        self.seen = apk_path
        if self.exc is not None:
            raise self.exc
        return FakeEnvelope(self.payload)


class FakeCodeIntelEngine:
    def __init__(self, payload: dict[str, Any] | None = None, exc: Exception | None = None) -> None:
        self.payload = payload or {"envelope_version": "1.0", "status": "ok", "findings": []}
        self.exc = exc
        self.kwargs: dict[str, Any] = {}

    def analyze(self, static_evidence: dict[str, Any], **kwargs: Any) -> FakeEnvelope:
        self.kwargs = {"static_evidence": static_evidence, **kwargs}
        if self.exc is not None:
            raise self.exc
        return FakeEnvelope(self.payload)


class FakeEvidenceRow:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload


class FakeEvidenceRepo:
    """Returns canned envelopes, recording which engine was asked for."""

    rows: dict[str, list[FakeEvidenceRow]] = {}

    def __init__(self, _session: Any) -> None:
        pass

    async def list_for_job(self, _job_id: Any, *, engine: str | None = None):
        return FakeEvidenceRepo.rows.get(engine or "", [])


@pytest.fixture
def sample() -> Sample:
    return Sample(sha256="ab" * 32, file_size=1234, storage_uri="file:///tmp/x.apk")


@pytest.fixture(autouse=True)
def _reset_repo():
    FakeEvidenceRepo.rows = {}
    yield
    FakeEvidenceRepo.rows = {}


@pytest.fixture(autouse=True)
def _stub_apk(monkeypatch, tmp_path: Path):
    """Pretend the APK materializes out of object storage."""

    async def _fake(sample: Sample, dest_dir: Path) -> Path:
        dest_dir.mkdir(parents=True, exist_ok=True)
        apk = dest_dir / f"{sample.sha256}.apk"
        apk.write_bytes(b"PK\x03\x04")
        return apk

    monkeypatch.setattr(st, "materialize_apk", _fake)


# ---------------------------------------------------------------------------
# Static
# ---------------------------------------------------------------------------


async def _run_static(stage: FakeStageRunner, engine: Any, sample: Sample, tmp_path: Path):
    return await st._execute(
        stage=stage,  # type: ignore[arg-type]
        engine=engine,
        sample=sample,
        job_id="job-1",
        input_dir=tmp_path / "input",
    )


@pytest.mark.asyncio
async def test_static_happy_path_completes_with_the_envelope(
    sample: Sample, tmp_path: Path
) -> None:
    stage, engine = FakeStageRunner(), FakeStaticEngine({"status": "ok", "findings": []})

    outcome = await _run_static(stage, engine, sample, tmp_path)

    assert stage.calls == ["begin", "complete"]
    assert outcome.status is StageStatus.ok
    # The engine is handed the materialized path, not a storage key.
    assert engine.seen is not None and engine.seen.name.endswith(".apk")


@pytest.mark.asyncio
async def test_static_disabled_skips_before_touching_storage(
    sample: Sample, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(st.settings, "static_enabled", False)
    stage, engine = FakeStageRunner(), FakeStaticEngine()

    outcome = await _run_static(stage, engine, sample, tmp_path)

    assert stage.calls == ["begin", "skip"]
    assert outcome.status is StageStatus.skipped
    # Never copy a malware sample out of storage for a stage that will not run it.
    assert engine.seen is None


@pytest.mark.asyncio
async def test_static_missing_apk_bytes_fail_the_stage(
    sample: Sample, tmp_path: Path, monkeypatch
) -> None:
    async def _boom(sample: Sample, dest_dir: Path) -> Path:
        raise FileNotFoundError("samples/ab/ab/....apk")

    monkeypatch.setattr(st, "materialize_apk", _boom)
    stage, engine = FakeStageRunner(), FakeStaticEngine()

    outcome = await _run_static(stage, engine, sample, tmp_path)

    assert stage.calls == ["begin", "fail"]
    assert outcome.status is StageStatus.failed
    assert engine.seen is None


@pytest.mark.asyncio
async def test_static_engine_error_fails_the_stage_only(sample: Sample, tmp_path: Path) -> None:
    stage = FakeStageRunner()
    engine = FakeStaticEngine(exc=RuntimeError("androguard blew up"))

    outcome = await _run_static(stage, engine, sample, tmp_path)

    assert stage.calls == ["begin", "fail"]
    assert outcome.status is StageStatus.failed
    assert "androguard blew up" in (stage.reason or "")


# ---------------------------------------------------------------------------
# Code intel
# ---------------------------------------------------------------------------


async def _run_code_intel(stage: FakeStageRunner, engine: Any, sample: Sample, monkeypatch):
    monkeypatch.setattr(ci, "EvidenceRepository", FakeEvidenceRepo)
    import uuid

    return await ci._execute(
        session=None,  # type: ignore[arg-type]
        stage=stage,  # type: ignore[arg-type]
        engine=engine,
        sample=sample,
        job_id="job-1",
        jid=uuid.uuid4(),
    )


@pytest.mark.asyncio
async def test_code_intel_reads_the_static_envelopes_evidence(sample: Sample, monkeypatch) -> None:
    FakeEvidenceRepo.rows = {
        "static": [FakeEvidenceRow({"evidence": {"permissions": {"permissions": ["INTERNET"]}}})]
    }
    stage, engine = FakeStageRunner("code_intel"), FakeCodeIntelEngine()

    outcome = await _run_code_intel(stage, engine, sample, monkeypatch)

    assert stage.calls == ["begin", "complete"]
    assert outcome.status is StageStatus.ok
    assert engine.kwargs["static_evidence"] == {"permissions": {"permissions": ["INTERNET"]}}
    assert engine.kwargs["apk_sha256"] == sample.sha256


@pytest.mark.asyncio
async def test_code_intel_skips_when_static_produced_nothing(sample: Sample, monkeypatch) -> None:
    # A skip, not a failure: the absence is a statement about the static stage.
    FakeEvidenceRepo.rows = {}
    stage, engine = FakeStageRunner("code_intel"), FakeCodeIntelEngine()

    outcome = await _run_code_intel(stage, engine, sample, monkeypatch)

    assert stage.calls == ["begin", "skip"]
    assert outcome.status is StageStatus.skipped
    assert "static evidence" in (stage.reason or "")
    assert engine.kwargs == {}


@pytest.mark.asyncio
async def test_code_intel_skips_an_empty_static_envelope(sample: Sample, monkeypatch) -> None:
    FakeEvidenceRepo.rows = {"static": [FakeEvidenceRow({"evidence": {}})]}
    stage, engine = FakeStageRunner("code_intel"), FakeCodeIntelEngine()

    outcome = await _run_code_intel(stage, engine, sample, monkeypatch)

    assert stage.calls == ["begin", "skip"]
    assert outcome.status is StageStatus.skipped


@pytest.mark.asyncio
async def test_code_intel_disabled_skips(sample: Sample, monkeypatch) -> None:
    monkeypatch.setattr(ci.settings, "code_intel_enabled", False)
    stage, engine = FakeStageRunner("code_intel"), FakeCodeIntelEngine()

    outcome = await _run_code_intel(stage, engine, sample, monkeypatch)

    assert stage.calls == ["begin", "skip"]
    assert outcome.status is StageStatus.skipped


@pytest.mark.asyncio
async def test_code_intel_engine_error_fails_the_stage_only(sample: Sample, monkeypatch) -> None:
    FakeEvidenceRepo.rows = {"static": [FakeEvidenceRow({"evidence": {"smali": {}}})]}
    stage = FakeStageRunner("code_intel")
    engine = FakeCodeIntelEngine(exc=RuntimeError("analyzer crashed"))

    outcome = await _run_code_intel(stage, engine, sample, monkeypatch)

    assert stage.calls == ["begin", "fail"]
    assert outcome.status is StageStatus.failed


class TestDecompiledTree:
    """The static → code-intel artifact handoff, local-disk half.

    ``artifact_dir`` is a path on the worker's own filesystem, so it is verified
    rather than trusted: a stale path would make the analyzers read an empty tree
    and silently report less than they could.

    The evidence key is ``decompiled_java``, and that is load-bearing — see
    ``test_the_evidence_key_matches_the_engines_extractor_name``.
    """

    def test_the_evidence_key_matches_the_engines_extractor_name(self) -> None:
        # The static pipeline files each extractor's evidence under `extractor.name`.
        # This lookup read `evidence["decompile"]` while the extractor is called
        # `decompiled_java`, so the tree was never found — on a single-worker
        # deployment either. Both this test and the ones below encoded the wrong key,
        # which is why nothing noticed.
        from sephela_static.extractors.decompile import DecompileExtractor

        assert DecompileExtractor.name == "decompiled_java"

    def test_an_existing_tree_is_passed_through(self, tmp_path: Path) -> None:
        tree = tmp_path / "jadx"
        tree.mkdir()

        found = ci.decompiled_tree({"evidence": {"decompiled_java": {"artifact_dir": str(tree)}}})

        assert found == tree

    def test_a_vanished_tree_degrades_to_none(self, tmp_path: Path) -> None:
        # The case that bites on a multi-worker deployment: static ran elsewhere.
        missing = tmp_path / "gone"
        payload = {"evidence": {"decompiled_java": {"artifact_dir": str(missing)}}}

        assert ci.decompiled_tree(payload) is None

    def test_a_file_is_not_a_tree(self, tmp_path: Path) -> None:
        f = tmp_path / "jadx"
        f.write_text("not a directory")

        assert (
            ci.decompiled_tree({"evidence": {"decompiled_java": {"artifact_dir": str(f)}}}) is None
        )

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"evidence": None},
            {"evidence": {}},
            {"evidence": {"decompiled_java": None}},
            {"evidence": {"decompiled_java": {}}},
            {"evidence": {"decompiled_java": {"artifact_dir": ""}}},
            {"evidence": {"decompiled_java": {"artifact_dir": 42}}},
        ],
    )
    def test_malformed_evidence_is_tolerated(self, payload: dict[str, Any]) -> None:
        # Evidence comes from a process that parsed a malware sample; it is
        # untrusted input and must never raise here.
        assert ci.decompiled_tree(payload) is None


@pytest.mark.asyncio
async def test_code_intel_passes_the_tree_when_it_exists(
    sample: Sample, tmp_path: Path, monkeypatch
) -> None:
    tree = tmp_path / "jadx"
    tree.mkdir()
    FakeEvidenceRepo.rows = {
        "static": [
            FakeEvidenceRow(
                {"evidence": {"smali": {}, "decompiled_java": {"artifact_dir": str(tree)}}}
            )
        ]
    }
    stage, engine = FakeStageRunner("code_intel"), FakeCodeIntelEngine()

    await _run_code_intel(stage, engine, sample, monkeypatch)

    assert engine.kwargs["artifact_dir"] == tree


@pytest.mark.asyncio
async def test_code_intel_still_runs_without_the_tree(sample: Sample, monkeypatch) -> None:
    # Degraded depth, not a failed stage — the engine treats the tree as optional.
    FakeEvidenceRepo.rows = {
        "static": [FakeEvidenceRow({"evidence": {"smali": {}, "decompiled_java": {}}})]
    }
    stage, engine = FakeStageRunner("code_intel"), FakeCodeIntelEngine()

    outcome = await _run_code_intel(stage, engine, sample, monkeypatch)

    assert outcome.status is StageStatus.ok
    assert engine.kwargs["artifact_dir"] is None
