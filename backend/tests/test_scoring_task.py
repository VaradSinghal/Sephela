"""Tests for the scoring stage and its finding adapter.

The load-bearing property here is independence: ``RiskScoringEngine`` is pure
computation over findings, so a deployment with no LLM credential still gets a
score. If a refactor ever made this stage require the AI envelope, these tests
should fail.

The adapter gets its own tests because the ORM and the scoring engine were written
against different vocabularies, and a silent mismatch there does not crash — it
quietly produces a wrong score.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.db.models.analysis import Finding, StageStatus
from app.services.stages import StageOutcome
from app.tasks import scoring as sc


class FakeStageRunner:
    def __init__(self) -> None:
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
        return StageOutcome(engine="scoring", status=StageStatus.ok)

    async def fail(self, exc: BaseException | str) -> StageOutcome:
        self.calls.append("fail")
        self.reason = str(exc)
        return StageOutcome(engine="scoring", status=StageStatus.failed, error=str(exc))

    async def skip(self, reason: str) -> StageOutcome:
        self.calls.append("skip")
        self.reason = reason
        return StageOutcome(engine="scoring", status=StageStatus.skipped, error=reason)

    async def set_progress(self, progress: int) -> None:
        self.progress = progress


class FakeSession:
    def __init__(self) -> None:
        self.commits = 0

    async def commit(self) -> None:
        self.commits += 1


class FakeJob:
    def __init__(self) -> None:
        self.id = uuid.uuid4()
        self.risk_score: float | None = None
        self.risk_tier: str | None = None


class FakeFindingRepo:
    rows: list[Finding] = []

    def __init__(self, _session: Any) -> None:
        pass

    async def list_for_job(self, _job_id: Any, **_: Any) -> list[Finding]:
        return FakeFindingRepo.rows


class FakeEvidenceRow:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload


class FakeEvidenceRepo:
    rows: dict[str, list[FakeEvidenceRow]] = {}

    def __init__(self, _session: Any) -> None:
        pass

    async def list_for_job(self, _job_id: Any, *, engine: str | None = None):
        return FakeEvidenceRepo.rows.get(engine or "", [])


def _finding(**kwargs: Any) -> Finding:
    defaults: dict[str, Any] = {
        "id": uuid.uuid4(),
        "job_id": uuid.uuid4(),
        "evidence_id": None,
        "source_engine": "static",
        "finding_id": "static-1",
        "type": "accessibility_service_abuse",
        "severity": "critical",
        "confidence": 0.9,
        "detail": "Requests BIND_ACCESSIBILITY_SERVICE",
        "provenance": None,
        "mitre": ["T1417"],
        "owasp_mobile": ["M1"],
    }
    defaults.update(kwargs)
    return Finding(**defaults)


@pytest.fixture(autouse=True)
def _reset():
    FakeFindingRepo.rows = []
    FakeEvidenceRepo.rows = {}
    yield
    FakeFindingRepo.rows = []
    FakeEvidenceRepo.rows = {}


@pytest.fixture(autouse=True)
def _patch_repos(monkeypatch):
    monkeypatch.setattr(sc, "FindingRepository", FakeFindingRepo)
    monkeypatch.setattr(sc, "EvidenceRepository", FakeEvidenceRepo)


async def _run(stage: FakeStageRunner, job: FakeJob, session: FakeSession):
    return await sc._execute(
        session=session,  # type: ignore[arg-type]
        stage=stage,  # type: ignore[arg-type]
        job=job,  # type: ignore[arg-type]
        job_id=str(job.id),
        jid=job.id,
    )


class TestConfidenceLabel:
    """Float confidence → the scoring engine's label buckets."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (1.0, "very_high"),
            (0.95, "very_high"),
            (0.94, "high"),
            (0.75, "high"),
            (0.74, "medium"),
            (0.45, "medium"),
            (0.44, "low"),
            (0.0, "low"),
        ],
    )
    def test_buckets(self, value: float, expected: str) -> None:
        assert sc.confidence_label(value) == expected

    def test_an_unstated_confidence_does_not_inflate_the_score(self) -> None:
        # medium is the neutral bucket, not the most favourable one: an engine
        # that declined to state a confidence must not get the benefit of the
        # doubt.
        assert sc.confidence_label(None) == "medium"

    def test_the_labels_match_the_scoring_engines_own_table(self) -> None:
        # The buckets are only correct if they name keys the engine recognises;
        # a renamed key would silently fall back to the engine's default.
        from ai.scoring.constants import CONFIDENCE_MULTIPLIERS

        labels = {sc.confidence_label(v) for v in (None, 0.0, 0.5, 0.8, 0.99)}
        assert labels <= set(CONFIDENCE_MULTIPLIERS)


class TestFindingAdapter:
    def test_the_orm_vocabulary_is_translated(self) -> None:
        row = _finding(mitre=["T1417", "T1631"], owasp_mobile=["M1"], detail="overlay abuse")

        adapted = sc.to_scoring_finding(row)

        # These four renames are the whole reason the adapter exists.
        assert adapted["mitre_techniques"] == ["T1417", "T1631"]
        assert adapted["description"] == "overlay abuse"
        assert adapted["confidence"] == "high"
        assert adapted["title"] == "accessibility_service_abuse"

    def test_null_columns_become_empty_rather_than_none(self) -> None:
        row = _finding(detail=None, mitre=None, owasp_mobile=None, confidence=None)

        adapted = sc.to_scoring_finding(row)

        assert adapted["description"] == ""
        assert adapted["mitre_techniques"] == []
        assert adapted["owasp_mobile"] == []
        assert adapted["confidence"] == "medium"

    def test_the_evidence_id_is_carried_as_a_reference(self) -> None:
        evidence_id = uuid.uuid4()

        adapted = sc.to_scoring_finding(_finding(evidence_id=evidence_id))

        # Provenance is what makes a score defensible rather than asserted.
        assert adapted["evidence_refs"] == [str(evidence_id)]

    def test_a_finding_without_evidence_has_no_refs(self) -> None:
        assert sc.to_scoring_finding(_finding(evidence_id=None))["evidence_refs"] == []


class TestTypeVocabulary:
    """The engines' finding types vs. the scoring engine's domain table.

    ``_group_by_domain`` defaults an unrecognised type to ``code`` rather than
    raising, so every mismatch here is silent: the score still comes out, it is
    just decomposed under the wrong heading.
    """

    def test_cert_is_translated_to_the_tables_spelling(self) -> None:
        # Both engines emit "cert"; the table spells it "certificate". Untranslated,
        # a debug-signed banking app is filed under code instead of manifest.
        assert sc.scoring_type("static", "cert") == "certificate"

    def test_a_static_signature_is_not_attributed_to_threat_intel(self) -> None:
        # The static engine's "signature" is a packer/anti-VM match. Left alone it
        # would credit threat intelligence for a verdict no feed contributed to.
        assert sc.scoring_type("static", "signature") == "anti_analysis"
        assert sc.scoring_type("code_intel", "signature") == "anti_analysis"

    def test_a_threat_intel_signature_keeps_its_meaning(self) -> None:
        assert sc.scoring_type("threat_intel", "signature") == "signature"

    def test_unambiguous_types_pass_through(self) -> None:
        for type_ in ("permission", "api", "url", "ip", "behavior", "obfuscation"):
            assert sc.scoring_type("static", type_) == type_

    def test_every_translated_type_lands_in_a_real_domain(self) -> None:
        # The point of translating is to hit the table. If a translation names a key
        # the table lacks, it silently defaults to `code` and buys nothing.
        from ai.scoring.constants import DOMAIN_WEIGHTS, FINDING_TYPE_TO_DOMAIN

        for target in {*sc._TYPE_ALIASES.values(), *sc._TYPE_ALIASES_BY_ENGINE.values()}:
            assert target in FINDING_TYPE_TO_DOMAIN, f"{target} is not in the domain table"
            assert FINDING_TYPE_TO_DOMAIN[target] in DOMAIN_WEIGHTS

    def test_the_engines_own_finding_types_are_all_mapped(self) -> None:
        # Every type the static/code-intel engines can emit should reach a real
        # domain, whether directly or through an alias. This is the test that fails
        # when an engine gains a finding type and nobody tells the scoring table.
        from ai.scoring.constants import FINDING_TYPE_TO_DOMAIN
        from sephela_static.envelope import FindingType

        unmapped = [
            t.value
            for t in FindingType
            if sc.scoring_type("static", t.value) not in FINDING_TYPE_TO_DOMAIN
        ]
        assert unmapped == [], f"static engine types absent from the domain table: {unmapped}"


class TestScoringStage:
    @pytest.mark.asyncio
    async def test_it_scores_findings_and_denormalises_onto_the_job(self) -> None:
        FakeFindingRepo.rows = [_finding(), _finding(finding_id="static-2", severity="high")]
        stage, job, session = FakeStageRunner(), FakeJob(), FakeSession()

        outcome = await _run(stage, job, session)

        assert stage.calls == ["begin", "complete"]
        assert outcome.status is StageStatus.ok
        assert stage.payload is not None
        assert stage.payload["risk_score"] > 0
        assert stage.payload["scored_findings"] == 2
        # Denormalised so job lists can rank without joining evidence.
        assert job.risk_score == stage.payload["risk_score"]
        assert job.risk_tier == stage.payload["risk_tier"]

    @pytest.mark.asyncio
    async def test_it_runs_with_no_ai_envelope_at_all(self) -> None:
        # The property that matters: no LLM credential still yields a score.
        FakeEvidenceRepo.rows = {}
        FakeFindingRepo.rows = [_finding()]
        stage, job, session = FakeStageRunner(), FakeJob(), FakeSession()

        outcome = await _run(stage, job, session)

        assert outcome.status is StageStatus.ok
        assert job.risk_score is not None

    @pytest.mark.asyncio
    async def test_the_persisted_tier_is_a_plain_string_not_an_enum(self) -> None:
        # asdict() keeps a RiskTierEnum member as-is, which reads back as
        # "RiskTierEnum.benign" anywhere it is stringified rather than JSON-encoded.
        FakeFindingRepo.rows = [_finding()]
        stage, job, session = FakeStageRunner(), FakeJob(), FakeSession()

        await _run(stage, job, session)

        assert stage.payload is not None
        tier = stage.payload["evidence"]["scoring"]["tier"]
        assert isinstance(tier, str)
        assert "RiskTierEnum" not in tier
        assert tier == stage.payload["risk_tier"] == job.risk_tier

    @pytest.mark.asyncio
    async def test_the_envelope_keeps_the_breakdown_not_just_the_number(self) -> None:
        # A bare score is not defensible to an auditor; the per-domain
        # decomposition is what the report and the dashboard render.
        FakeFindingRepo.rows = [_finding()]
        stage, job, session = FakeStageRunner(), FakeJob(), FakeSession()

        await _run(stage, job, session)

        assert stage.payload is not None
        block = stage.payload["evidence"]["scoring"]
        assert "domain_scores" in block
        assert "synergy_bonuses" in block
        assert "final_score" in block

    @pytest.mark.asyncio
    async def test_no_findings_skips_rather_than_scoring_zero(self) -> None:
        # Nothing to score is not a clean bill of health, and a 0.0 would read as
        # one on every dashboard.
        FakeFindingRepo.rows = []
        stage, job, session = FakeStageRunner(), FakeJob(), FakeSession()

        outcome = await _run(stage, job, session)

        assert stage.calls == ["begin", "skip"]
        assert outcome.status is StageStatus.skipped
        assert job.risk_score is None

    @pytest.mark.asyncio
    async def test_disabled_skips(self, monkeypatch) -> None:
        monkeypatch.setattr(sc.settings, "scoring_enabled", False)
        FakeFindingRepo.rows = [_finding()]
        stage, job, session = FakeStageRunner(), FakeJob(), FakeSession()

        outcome = await _run(stage, job, session)

        assert stage.calls == ["begin", "skip"]
        assert outcome.status is StageStatus.skipped

    @pytest.mark.asyncio
    async def test_static_permissions_are_passed_to_the_categoriser(self) -> None:
        FakeEvidenceRepo.rows = {
            "static": [
                FakeEvidenceRow(
                    {"evidence": {"permissions": {"permissions": ["android.permission.SEND_SMS"]}}}
                )
            ]
        }
        FakeFindingRepo.rows = [_finding()]
        stage, job, session = FakeStageRunner(), FakeJob(), FakeSession()

        outcome = await _run(stage, job, session)

        assert outcome.status is StageStatus.ok

    @pytest.mark.asyncio
    async def test_an_engine_error_fails_the_stage_only(self, monkeypatch) -> None:
        FakeFindingRepo.rows = [_finding()]
        stage, job, session = FakeStageRunner(), FakeJob(), FakeSession()

        class Boom:
            def __init__(self, *a: Any, **k: Any) -> None:
                pass

            def score(self, *a: Any, **k: Any) -> Any:
                raise RuntimeError("weights are broken")

        import ai.scoring

        monkeypatch.setattr(ai.scoring, "RiskScoringEngine", Boom)

        outcome = await _run(stage, job, session)

        assert stage.calls == ["begin", "fail"]
        assert outcome.status is StageStatus.failed
        assert job.risk_score is None


class TestContextHarvesting:
    def test_permissions_are_read_from_the_static_envelope(self) -> None:
        payload = {"evidence": {"permissions": {"permissions": ["A", "B"]}}}

        assert sc._permissions(payload) == ["A", "B"]

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"evidence": None},
            {"evidence": {}},
            {"evidence": {"permissions": None}},
            {"evidence": {"permissions": {}}},
            {"evidence": {"permissions": {"permissions": None}}},
        ],
    )
    def test_malformed_static_evidence_yields_no_permissions(self, payload: dict) -> None:
        assert sc._permissions(payload) == []

    def test_non_string_permissions_are_dropped(self) -> None:
        payload = {"evidence": {"permissions": {"permissions": ["A", 42, None, "B"]}}}

        assert sc._permissions(payload) == ["A", "B"]

    def test_agent_outputs_are_read_when_the_ai_stage_ran(self) -> None:
        assert sc._agent_outputs({"agent_results": {"manifest": {"findings": []}}}) == {
            "manifest": {"findings": []}
        }

    def test_a_missing_ai_envelope_yields_no_agent_outputs(self) -> None:
        assert sc._agent_outputs({}) == {}
