"""Tests for report assembly and the reporting stage.

Two properties are pinned here:

- **A report needs no LLM.** ``build_report_data`` produces a valid
  ``AnalysisReport`` from persisted rows alone, and the reporting engine accepts
  it. This is validated against the engine's real pydantic models rather than a
  fake, because "would the renderer actually take this?" is the only version of
  the question that matters.
- **A missing optional renderer costs one format, not the report.** PDF needs
  weasyprint; four other formats need nothing.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from app.db.models.analysis import Finding, JobStatus, Sample, StageStatus
from app.services import reports as rp
from app.services.stages import StageOutcome
from app.tasks import reporting as rpt


class FakeStageRunner:
    def __init__(self) -> None:
        self.engine_version = "0.1.0"
        self.calls: list[str] = []
        self.payload: dict[str, Any] | None = None
        self.reason: str | None = None
        self.uri: str | None = None

    async def begin(self) -> str:
        self.calls.append("begin")
        return "stage-1"

    async def complete(
        self, payload: dict[str, Any], *, large_artifact_uri: str | None = None
    ) -> StageOutcome:
        self.calls.append("complete")
        self.payload = payload
        self.uri = large_artifact_uri
        return StageOutcome(engine="reporting", status=StageStatus.ok)

    async def fail(self, exc: BaseException | str) -> StageOutcome:
        self.calls.append("fail")
        self.reason = str(exc)
        return StageOutcome(engine="reporting", status=StageStatus.failed, error=str(exc))

    async def skip(self, reason: str) -> StageOutcome:
        self.calls.append("skip")
        self.reason = reason
        return StageOutcome(engine="reporting", status=StageStatus.skipped, error=reason)

    async def set_progress(self, progress: int) -> None:
        pass


class FakeJob:
    def __init__(self, risk_score: float | None = None, risk_tier: str | None = None) -> None:
        self.id = uuid.uuid4()
        self.pipeline_version = "1.0.0"
        self.status = JobStatus.completed
        self.risk_score = risk_score
        self.risk_tier = risk_tier


class FakeEvidence:
    def __init__(self, engine_name: str, payload: dict[str, Any]) -> None:
        self.engine_name = engine_name
        self.payload = payload
        self.created_at = datetime.now(UTC)


class FakeEvidenceRepo:
    rows: list[FakeEvidence] = []

    def __init__(self, _session: Any) -> None:
        pass

    async def list_for_job(self, _job_id: Any, *, engine: str | None = None):
        if engine is None:
            return FakeEvidenceRepo.rows
        return [r for r in FakeEvidenceRepo.rows if r.engine_name == engine]


class FakeFindingRepo:
    rows: list[Finding] = []

    def __init__(self, _session: Any) -> None:
        pass

    async def list_for_job(self, _job_id: Any, **_: Any) -> list[Finding]:
        return FakeFindingRepo.rows


class FakeArtifact:
    def __init__(self, filename: str, data: bytes = b"x") -> None:
        self.filename = filename
        self.content_bytes = data


class FakeStorage:
    def __init__(self) -> None:
        self.saved: dict[str, bytes] = {}

    async def save(self, key: str, data: bytes) -> str:
        self.saved[key] = data
        return f"file:///{key}"


@pytest.fixture
def sample() -> Sample:
    return Sample(
        sha256="ab" * 32,
        file_size=4096,
        storage_uri="file:///tmp/x.apk",
        original_filename="fake-bank.apk",
        package_name="com.fake.bank",
    )


def _finding(**kwargs: Any) -> Finding:
    defaults: dict[str, Any] = {
        "id": uuid.uuid4(),
        "job_id": uuid.uuid4(),
        "evidence_id": None,
        "source_engine": "static",
        "finding_id": "static-1",
        "type": "overlay_abuse",
        "severity": "critical",
        "confidence": 0.9,
        "detail": "Draws over other apps",
        "provenance": {"extractor": "manifest", "path": "AndroidManifest.xml"},
        "mitre": ["T1417"],
        "owasp_mobile": ["M1"],
    }
    defaults.update(kwargs)
    return Finding(**defaults)


_SCORING = {
    "evidence": {
        "scoring": {
            "final_score": 87.5,
            "base_score": 80.0,
            "synergy_bonus": 7.5,
            "tier": "malicious",
            "confidence": 0.9,
            "primary_category": "banking_trojan",
            "key_findings": ["Accessibility abuse"],
            "domain_scores": [],
            "synergy_bonuses": [],
        }
    }
}


@pytest.fixture(autouse=True)
def _reset():
    FakeEvidenceRepo.rows = []
    FakeFindingRepo.rows = []
    yield
    FakeEvidenceRepo.rows = []
    FakeFindingRepo.rows = []


class TestReportAssembly:
    def test_the_engine_accepts_a_report_built_with_no_ai_and_no_score(
        self, sample: Sample
    ) -> None:
        # The floor case: only static analysis ran. Still a valid report.
        from sephela_reporting.models import AnalysisReport

        data = rp.build_report_data(
            job=FakeJob(),  # type: ignore[arg-type]
            sample=sample,
            evidence_rows=[FakeEvidence("static", {"evidence": {"permissions": {}}})],  # type: ignore[list-item]
            finding_rows=[_finding()],
        )

        AnalysisReport.model_validate(data)  # raises if the shape is wrong

    def test_the_engine_accepts_a_scored_report(self, sample: Sample) -> None:
        from sephela_reporting.models import AnalysisReport

        data = rp.build_report_data(
            job=FakeJob(),  # type: ignore[arg-type]
            sample=sample,
            evidence_rows=[FakeEvidence("scoring", _SCORING)],  # type: ignore[list-item]
            finding_rows=[_finding()],
        )

        report = AnalysisReport.model_validate(data)
        assert report.executive_summary.risk_score == 87.5
        assert report.executive_summary.risk_tier == "malicious"
        assert report.executive_summary.primary_category == "banking_trojan"

    def test_an_unscored_job_is_not_reported_as_benign(self, sample: Sample) -> None:
        # The renderer's schema requires a float, so risk_score falls back to 0.0.
        # That makes the tier load-bearing: "benign" here would turn "we did not
        # score this" into a clean bill of health.
        data = rp.build_report_data(
            job=FakeJob(),  # type: ignore[arg-type]
            sample=sample,
            evidence_rows=[FakeEvidence("static", {"evidence": {}})],  # type: ignore[list-item]
            finding_rows=[_finding()],
        )

        summary = data["executive_summary"]
        assert summary["risk_tier"] == "unknown"
        assert "No risk score was computed" in summary["overview"]
        assert not any("hostile" in a for a in summary["recommended_actions"])

    def test_an_enum_tier_is_unwrapped_before_it_reaches_a_renderer(self, sample: Sample) -> None:
        # dataclasses.asdict keeps a RiskTierEnum member as-is, and a stringified
        # enum reaches the reader as "RiskTierEnum.malicious" in a document a bank
        # forwards to a regulator.
        from ai.scoring.models import RiskTierEnum

        scoring = {"evidence": {"scoring": {**_SCORING["evidence"]["scoring"]}}}
        scoring["evidence"]["scoring"]["tier"] = RiskTierEnum.malicious

        data = rp.build_report_data(
            job=FakeJob(),  # type: ignore[arg-type]
            sample=sample,
            evidence_rows=[FakeEvidence("scoring", scoring)],  # type: ignore[list-item]
            finding_rows=[_finding()],
        )

        assert data["executive_summary"]["risk_tier"] == "malicious"
        assert "RiskTierEnum" not in data["executive_summary"]["overview"]

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("malicious", "malicious"),
            ("RiskTierEnum.critical", "critical"),
            ("  Benign  ", "benign"),
            ("nonsense", None),
            (None, None),
        ],
    )
    def test_tier_normalisation(self, raw: Any, expected: str | None) -> None:
        assert rp._tier_name(raw) == expected

    def test_findings_are_ranked_worst_first(self, sample: Sample) -> None:
        rows = [
            _finding(finding_id="a", severity="low"),
            _finding(finding_id="b", severity="critical"),
            _finding(finding_id="c", severity="medium"),
        ]

        data = rp.build_report_data(
            job=FakeJob(),  # type: ignore[arg-type]
            sample=sample,
            evidence_rows=[FakeEvidence("static", {"evidence": {}})],  # type: ignore[list-item]
            finding_rows=rows,
        )

        assert [f["severity"] for f in data["findings"]] == ["critical", "medium", "low"]

    def test_an_unknown_severity_is_coerced_rather_than_failing_validation(
        self, sample: Sample
    ) -> None:
        # Engines are separate distributions; one emitting an unexpected label
        # must not cost the whole report.
        from sephela_reporting.models import AnalysisReport

        data = rp.build_report_data(
            job=FakeJob(),  # type: ignore[arg-type]
            sample=sample,
            evidence_rows=[FakeEvidence("static", {"evidence": {}})],  # type: ignore[list-item]
            finding_rows=[_finding(severity="catastrophic")],
        )

        AnalysisReport.model_validate(data)
        assert data["findings"][0]["severity"] == "info"

    def test_compliance_mapping_is_inverted_from_the_findings(self, sample: Sample) -> None:
        rows = [
            _finding(finding_id="a", mitre=["T1417"], owasp_mobile=["M1"]),
            _finding(finding_id="b", mitre=["T1417", "T1631"], owasp_mobile=[]),
        ]

        data = rp.build_report_data(
            job=FakeJob(),  # type: ignore[arg-type]
            sample=sample,
            evidence_rows=[FakeEvidence("static", {"evidence": {}})],  # type: ignore[list-item]
            finding_rows=rows,
        )

        mapping = data["compliance_mapping"]
        assert sorted(mapping["mitre_attack"]["T1417"]) == ["a", "b"]
        assert mapping["mitre_attack"]["T1631"] == ["b"]
        assert mapping["owasp_mobile"]["M1"] == ["a"]

    def test_provenance_survives_into_the_report(self, sample: Sample) -> None:
        # Evidence-linked findings are the product; a report that dropped
        # provenance would be an unsupported assertion.
        data = rp.build_report_data(
            job=FakeJob(),  # type: ignore[arg-type]
            sample=sample,
            evidence_rows=[FakeEvidence("static", {"evidence": {}})],  # type: ignore[list-item]
            finding_rows=[_finding()],
        )

        ref = data["findings"][0]["evidence_refs"][0]
        assert ref["extractor"] == "manifest"
        assert ref["path"] == "AndroidManifest.xml"

    def test_per_engine_evidence_lands_in_its_technical_section(self, sample: Sample) -> None:
        rows = [
            FakeEvidence("static", {"evidence": {"permissions": {"count": 3}}}),
            FakeEvidence("code_intel", {"evidence": {"summarizer": {"code_summary": {}}}}),
            FakeEvidence("threat_intel", {"evidence": {"verdicts": []}}),
        ]

        data = rp.build_report_data(
            job=FakeJob(),  # type: ignore[arg-type]
            sample=sample,
            evidence_rows=rows,  # type: ignore[arg-type]
            finding_rows=[],
        )

        technical = data["technical_details"]
        assert technical["static_analysis"] == {"permissions": {"count": 3}}
        assert technical["code_analysis"] == {"summarizer": {"code_summary": {}}}
        assert technical["threat_intel"] == {"verdicts": []}

    def test_an_ai_narrative_enriches_the_prose_but_not_the_numbers(self, sample: Sample) -> None:
        rows = [
            FakeEvidence("scoring", _SCORING),
            FakeEvidence(
                "ai_orchestrator",
                {
                    "agent_results": {"manifest": {}},
                    "report": {
                        "executive_summary": {
                            "overview": "An analyst-grade narrative.",
                            "business_impact": "Direct credential theft.",
                            "risk_score": 12.0,
                        }
                    },
                },
            ),
        ]

        data = rp.build_report_data(
            job=FakeJob(),  # type: ignore[arg-type]
            sample=sample,
            evidence_rows=rows,  # type: ignore[arg-type]
            finding_rows=[_finding()],
        )

        summary = data["executive_summary"]
        assert summary["overview"] == "An analyst-grade narrative."
        assert summary["business_impact"] == "Direct credential theft."
        # The score stays deterministic — the model does not get to move it.
        assert summary["risk_score"] == 87.5

    def test_an_empty_ai_narrative_does_not_blank_the_template(self, sample: Sample) -> None:
        rows = [
            FakeEvidence("scoring", _SCORING),
            FakeEvidence("ai_orchestrator", {"report": {"executive_summary": {"overview": "  "}}}),
        ]

        data = rp.build_report_data(
            job=FakeJob(),  # type: ignore[arg-type]
            sample=sample,
            evidence_rows=rows,  # type: ignore[arg-type]
            finding_rows=[_finding()],
        )

        assert data["executive_summary"]["overview"].startswith("Automated analysis")

    def test_the_report_id_is_stable_across_regeneration(self, sample: Sample) -> None:
        job = FakeJob()

        first = rp.build_report_data(
            job=job,  # type: ignore[arg-type]
            sample=sample,
            evidence_rows=[FakeEvidence("static", {"evidence": {}})],  # type: ignore[list-item]
            finding_rows=[],
        )
        second = rp.build_report_data(
            job=job,  # type: ignore[arg-type]
            sample=sample,
            evidence_rows=[FakeEvidence("static", {"evidence": {}})],  # type: ignore[list-item]
            finding_rows=[],
        )

        assert first["report_id"] == second["report_id"]

    def test_the_report_body_is_bounded(self, sample: Sample) -> None:
        rows = [_finding(finding_id=f"f-{i}") for i in range(rp.MAX_REPORT_FINDINGS + 50)]

        data = rp.build_report_data(
            job=FakeJob(),  # type: ignore[arg-type]
            sample=sample,
            evidence_rows=[FakeEvidence("static", {"evidence": {}})],  # type: ignore[list-item]
            finding_rows=rows,
        )

        assert len(data["findings"]) == rp.MAX_REPORT_FINDINGS

    def test_recommended_actions_escalate_with_the_tier(self) -> None:
        assert any("hostile" in a for a in rp._recommended_actions("malicious"))
        assert any("manual review" in a for a in rp._recommended_actions("suspicious"))
        assert any("No automated action" in a for a in rp._recommended_actions("benign"))
        assert rp._recommended_actions(None)


class TestReportingStage:
    async def _run(self, stage: FakeStageRunner, engine_cls: Any, sample: Sample):
        job = FakeJob()
        return await rpt._execute(
            session=None,  # type: ignore[arg-type]
            stage=stage,  # type: ignore[arg-type]
            engine_cls=engine_cls,
            job=job,  # type: ignore[arg-type]
            sample=sample,
            job_id=str(job.id),
            jid=job.id,
        )

    @pytest.fixture(autouse=True)
    def _patch(self, monkeypatch):
        self.storage = FakeStorage()
        monkeypatch.setattr(rpt, "EvidenceRepository", FakeEvidenceRepo)
        monkeypatch.setattr(rpt, "FindingRepository", FakeFindingRepo)
        monkeypatch.setattr(rpt, "storage", lambda: self.storage)

    @pytest.mark.asyncio
    async def test_every_rendered_format_is_persisted_and_manifested(self, sample: Sample) -> None:
        FakeEvidenceRepo.rows = [FakeEvidence("scoring", _SCORING)]
        FakeFindingRepo.rows = [_finding()]

        class Engine:
            def generate(self, data: dict, formats: list[str]) -> dict[str, Any]:
                return {f: FakeArtifact(f"report.{f}") for f in formats}

        stage = FakeStageRunner()
        outcome = await self._run(stage, Engine, sample)

        assert stage.calls == ["begin", "complete"]
        assert outcome.status is StageStatus.ok
        assert stage.payload is not None
        manifest = stage.payload["evidence"]["artifacts"]
        assert set(manifest) == set(rp.DEFAULT_FORMATS)
        # The bytes are in storage, not in the envelope's JSONB column.
        assert set(self.storage.saved) == set(manifest.values())
        assert stage.payload["status"] == "ok"

    @pytest.mark.asyncio
    async def test_a_missing_pdf_renderer_costs_one_format_not_the_report(
        self, sample: Sample
    ) -> None:
        FakeEvidenceRepo.rows = [FakeEvidence("scoring", _SCORING)]

        class Engine:
            def generate(self, data: dict, formats: list[str]) -> dict[str, Any]:
                # weasyprint absent: the engine returns what it could render.
                return {f: FakeArtifact(f"report.{f}") for f in formats if f != "pdf"}

        stage = FakeStageRunner()
        outcome = await self._run(stage, Engine, sample)

        assert outcome.status is StageStatus.ok
        assert stage.payload is not None
        assert "pdf" not in stage.payload["evidence"]["artifacts"]
        # Recorded as partial so the job detail page explains the gap.
        assert stage.payload["status"] == "partial"
        assert any("pdf" in e["message"] for e in stage.payload["errors"])

    @pytest.mark.asyncio
    async def test_a_total_render_failure_falls_back_to_dependency_free_formats(
        self, sample: Sample
    ) -> None:
        FakeEvidenceRepo.rows = [FakeEvidence("scoring", _SCORING)]

        class Engine:
            def __init__(self) -> None:
                self.attempts: list[list[str]] = []

            def generate(self, data: dict, formats: list[str]) -> dict[str, Any]:
                self.attempts.append(formats)
                if len(formats) > 2:
                    raise RuntimeError("renderer chain exploded")
                return {f: FakeArtifact(f"report.{f}") for f in formats}

        stage = FakeStageRunner()
        outcome = await self._run(stage, Engine, sample)

        assert outcome.status is StageStatus.ok
        assert stage.payload is not None
        assert set(stage.payload["evidence"]["artifacts"]) == {"json", "markdown"}

    @pytest.mark.asyncio
    async def test_the_primary_artifact_is_recorded_on_the_row(self, sample: Sample) -> None:
        FakeEvidenceRepo.rows = [FakeEvidence("scoring", _SCORING)]

        class Engine:
            def generate(self, data: dict, formats: list[str]) -> dict[str, Any]:
                return {f: FakeArtifact(f"report.{f}") for f in formats}

        stage = FakeStageRunner()
        await self._run(stage, Engine, sample)

        assert stage.uri is not None and "pdf" in stage.uri

    @pytest.mark.asyncio
    async def test_no_evidence_skips(self, sample: Sample) -> None:
        FakeEvidenceRepo.rows = []

        class Engine:
            def generate(self, data: dict, formats: list[str]) -> dict[str, Any]:
                raise AssertionError("must not be called")

        stage = FakeStageRunner()
        outcome = await self._run(stage, Engine, sample)

        assert stage.calls == ["begin", "skip"]
        assert outcome.status is StageStatus.skipped

    @pytest.mark.asyncio
    async def test_disabled_skips(self, sample: Sample, monkeypatch) -> None:
        monkeypatch.setattr(rpt.settings, "reporting_enabled", False)
        FakeEvidenceRepo.rows = [FakeEvidence("scoring", _SCORING)]

        class Engine:
            def generate(self, data: dict, formats: list[str]) -> dict[str, Any]:
                raise AssertionError("must not be called")

        stage = FakeStageRunner()
        outcome = await self._run(stage, Engine, sample)

        assert stage.calls == ["begin", "skip"]
        assert outcome.status is StageStatus.skipped

    @pytest.mark.asyncio
    async def test_rendering_nothing_at_all_fails_the_stage(self, sample: Sample) -> None:
        FakeEvidenceRepo.rows = [FakeEvidence("scoring", _SCORING)]

        class Engine:
            def generate(self, data: dict, formats: list[str]) -> dict[str, Any]:
                return {}

        stage = FakeStageRunner()
        outcome = await self._run(stage, Engine, sample)

        assert stage.calls == ["begin", "fail"]
        assert outcome.status is StageStatus.failed

    @pytest.mark.asyncio
    async def test_a_storage_failure_fails_the_stage(self, sample: Sample, monkeypatch) -> None:
        FakeEvidenceRepo.rows = [FakeEvidence("scoring", _SCORING)]

        class Broken:
            async def save(self, key: str, data: bytes) -> str:
                raise OSError("disk full")

        monkeypatch.setattr(rpt, "storage", lambda: Broken())

        class Engine:
            def generate(self, data: dict, formats: list[str]) -> dict[str, Any]:
                return {f: FakeArtifact(f"report.{f}") for f in formats}

        stage = FakeStageRunner()
        outcome = await self._run(stage, Engine, sample)

        assert stage.calls == ["begin", "fail"]
        assert outcome.status is StageStatus.failed


class TestStorageKeys:
    def test_report_keys_are_scoped_per_job_not_per_sample(self) -> None:
        # Two runs of the same sample are different jobs whose scores can
        # legitimately differ, so their reports must not collide.
        from app.storage.base import StorageBackend

        a = StorageBackend.report_key("11111111-1111-1111-1111-111111111111", "r.pdf")
        b = StorageBackend.report_key("22222222-2222-2222-2222-222222222222", "r.pdf")

        assert a != b
        assert a.startswith("reports/")
