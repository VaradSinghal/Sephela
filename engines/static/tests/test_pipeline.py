"""Static engine tests.

Runs the full pipeline over a synthetic APK. Tool-based extractors
(androguard/jadx/apkid) are expected to be ABSENT in CI, so the assertions
verify the isolation contract: tool-free extractors succeed, tool-based ones
land in ``errors``, and the run degrades to ``partial`` — never crashes.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from sephela_static import analyze
from sephela_static.base import ExtractionContext, Extractor, ExtractorResult
from sephela_static.envelope import (
    Finding,
    FindingType,
    Provenance,
    Severity,
    Status,
)
from sephela_static.extractors import default_extractors
from sephela_static.extractors.hashes import HashExtractor
from sephela_static.extractors.network import IpExtractor, UrlExtractor
from sephela_static.extractors.strings import StringExtractor


def _make_apk(tmp: Path) -> Path:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        # DEX-like blob carrying an embedded URL + public IP as printable strings.
        payload = (
            b"padding" * 3
            + b"https://evil-c2.example.com/gate.php"
            + b"\x00"
            + b"8.8.8.8"
            + b"\x00"
            + b"10.0.0.1"
        )
        zf.writestr("classes.dex", payload)
    path = tmp / "sample.apk"
    path.write_bytes(buf.getvalue())
    return path


def test_tool_free_extractors(tmp_path: Path) -> None:
    apk = _make_apk(tmp_path)
    ctx = ExtractionContext(apk_path=apk)

    h = HashExtractor().extract(ctx)
    assert len(h.evidence["sha256"]) == 64

    s = StringExtractor().extract(ctx)
    ctx.shared["strings"] = s.evidence
    assert s.evidence["count"] > 0

    urls = UrlExtractor().extract(ctx)
    assert "https://evil-c2.example.com/gate.php" in urls.evidence["urls"]
    assert len(urls.findings) == 1

    ips = IpExtractor().extract(ctx)
    assert "8.8.8.8" in ips.evidence["ips"]
    assert "10.0.0.1" not in ips.evidence["ips"]  # private IP filtered out


def test_full_pipeline_partial_when_tools_absent(tmp_path: Path) -> None:
    apk = _make_apk(tmp_path)
    env = analyze(apk, job_id="job-123")

    # Tool-free extractors always produce evidence.
    assert "hashes" in env.evidence
    assert "urls" in env.evidence
    assert env.apk_sha256 is not None
    assert env.job_id == "job-123"
    assert env.engine.name == "static"

    # Envelope is always valid regardless of tooling availability.
    assert env.status in (Status.ok, Status.partial)
    # Findings from tool-free extractors (the embedded URL) are present.
    assert any(f.type.value == "url" for f in env.findings)


def test_pipeline_never_raises_on_garbage(tmp_path: Path) -> None:
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"not a zip")
    env = analyze(bad)
    # Hashes still compute; zip-based extractors fail into errors, not crash.
    assert "hashes" in env.evidence
    assert env.status in (Status.ok, Status.partial, Status.failed)


# ---------------------------------------------------------------------------
# The isolation contract
# ---------------------------------------------------------------------------


class _Ok(Extractor):
    """An extractor that always succeeds."""

    def __init__(
        self, name: str, evidence: dict | None = None, findings: list | None = None
    ) -> None:
        self.name = name
        self._evidence = evidence if evidence is not None else {"ran": True}
        self._findings = findings or []

    def extract(self, ctx: ExtractionContext) -> ExtractorResult:
        return ExtractorResult(evidence=dict(self._evidence), findings=list(self._findings))


class _Boom(Extractor):
    """An extractor that always raises, the way a missing tool does."""

    def __init__(self, name: str, exc: Exception | None = None) -> None:
        self.name = name
        self._exc = exc or RuntimeError("tool not installed")

    def extract(self, ctx: ExtractionContext) -> ExtractorResult:
        raise self._exc


class _Reader(Extractor):
    """An extractor that reads an earlier one's evidence out of ``ctx.shared``."""

    name = "reader"

    def extract(self, ctx: ExtractionContext) -> ExtractorResult:
        return ExtractorResult(evidence={"saw": sorted(ctx.shared)})


def _finding(fid: str = "f1") -> Finding:
    return Finding(
        id=fid,
        type=FindingType.url,
        severity=Severity.info,
        confidence=0.5,
        detail="detail",
        provenance=Provenance(extractor="x"),
    )


class TestFailureIsolation:
    def test_one_failing_extractor_degrades_the_run_to_partial(self, tmp_path: Path) -> None:
        # The whole point of the design: a missing tool costs one extractor's evidence,
        # not the analysis.
        env = analyze(_make_apk(tmp_path), extractors=[_Ok("good"), _Boom("bad")])

        assert env.status is Status.partial
        assert env.evidence["good"] == {"ran": True}

    def test_the_failure_is_recorded_with_its_type_and_message(self, tmp_path: Path) -> None:
        # This is what an operator reads to know whether to install a tool or file a bug.
        env = analyze(
            _make_apk(tmp_path), extractors=[_Boom("bad", ValueError("malformed dex header"))]
        )

        (error,) = env.errors
        assert error.extractor == "bad"
        assert "ValueError" in error.message
        assert "malformed dex header" in error.message

    def test_every_extractor_failing_is_a_failed_run(self, tmp_path: Path) -> None:
        # Nothing was extracted, so calling it partial would overstate the result.
        env = analyze(_make_apk(tmp_path), extractors=[_Boom("a"), _Boom("b")])

        assert env.status is Status.failed
        assert len(env.errors) == 2

    def test_every_extractor_succeeding_is_an_ok_run(self, tmp_path: Path) -> None:
        env = analyze(_make_apk(tmp_path), extractors=[_Ok("a"), _Ok("b")])

        assert env.status is Status.ok
        assert env.errors == []

    def test_an_extractor_after_a_failure_still_runs(self, tmp_path: Path) -> None:
        # Order must not turn one broken tool into a cascade.
        env = analyze(_make_apk(tmp_path), extractors=[_Boom("bad"), _Ok("after")])

        assert "after" in env.evidence

    def test_a_keyboard_interrupt_is_not_swallowed_as_a_partial_failure(
        self, tmp_path: Path
    ) -> None:
        # BaseException is not an extractor problem; catching it would make the worker
        # unkillable during a long decompilation.
        with pytest.raises(KeyboardInterrupt):
            analyze(_make_apk(tmp_path), extractors=[_Boom("bad", KeyboardInterrupt())])

    def test_an_empty_chain_produces_a_valid_empty_envelope(self, tmp_path: Path) -> None:
        env = analyze(_make_apk(tmp_path), extractors=[])

        assert env.status is Status.ok
        assert env.evidence == {}
        assert env.findings == []


class TestFindingAggregation:
    def test_findings_from_every_extractor_are_collected(self, tmp_path: Path) -> None:
        env = analyze(
            _make_apk(tmp_path),
            extractors=[_Ok("a", findings=[_finding("a1")]), _Ok("b", findings=[_finding("b1")])],
        )

        assert {f.id for f in env.findings} == {"a1", "b1"}

    def test_findings_from_a_failed_extractor_are_lost_with_it(self, tmp_path: Path) -> None:
        # It raised part-way, so anything it had produced is not trustworthy.
        env = analyze(
            _make_apk(tmp_path), extractors=[_Boom("bad"), _Ok("ok", findings=[_finding()])]
        )

        assert len(env.findings) == 1

    def test_the_order_of_findings_follows_the_chain(self, tmp_path: Path) -> None:
        # Reports render in this order, and it should be reproducible run to run.
        env = analyze(
            _make_apk(tmp_path),
            extractors=[_Ok("a", findings=[_finding("a1")]), _Ok("b", findings=[_finding("b1")])],
        )

        assert [f.id for f in env.findings] == ["a1", "b1"]


class TestSharedEvidence:
    def test_an_extractor_sees_what_ran_before_it(self, tmp_path: Path) -> None:
        # How urls/ips read the string corpus and obfuscation reads the class list.
        env = analyze(_make_apk(tmp_path), extractors=[_Ok("first"), _Ok("second"), _Reader()])

        assert env.evidence["reader"]["saw"] == ["first", "second"]

    def test_it_does_not_see_what_runs_after_it(self, tmp_path: Path) -> None:
        env = analyze(_make_apk(tmp_path), extractors=[_Reader(), _Ok("later")])

        assert env.evidence["reader"]["saw"] == []

    def test_a_failed_extractor_contributes_nothing_to_shared(self, tmp_path: Path) -> None:
        # A dependent extractor must be able to tell "ran and found nothing" from "did
        # not run", and an empty dict in shared would blur the two.
        env = analyze(_make_apk(tmp_path), extractors=[_Boom("bad"), _Reader()])

        assert env.evidence["reader"]["saw"] == []


class TestEnvelopeMetadata:
    def test_the_sha256_is_promoted_from_the_hash_evidence(self, tmp_path: Path) -> None:
        # It is the top-level index and cache key, so it has to be lifted out of the
        # nested block the hash extractor writes.
        env = analyze(_make_apk(tmp_path), extractors=[HashExtractor()])

        assert env.apk_sha256 == env.evidence["hashes"]["sha256"]

    def test_without_a_hash_extractor_the_sha256_is_absent_rather_than_wrong(
        self, tmp_path: Path
    ) -> None:
        env = analyze(_make_apk(tmp_path), extractors=[_Ok("a")])

        assert env.apk_sha256 is None

    def test_malformed_hash_evidence_does_not_break_the_promotion(self, tmp_path: Path) -> None:
        env = analyze(_make_apk(tmp_path), extractors=[_Ok("hashes", evidence={"sha256": None})])

        assert env.apk_sha256 is None

    def test_the_job_id_is_carried_through(self, tmp_path: Path) -> None:
        env = analyze(_make_apk(tmp_path), job_id="job-abc", extractors=[_Ok("a")])

        assert env.job_id == "job-abc"

    def test_the_engine_identifies_and_versions_itself(self, tmp_path: Path) -> None:
        # Evidence outlives the code that produced it, so a stored envelope has to say
        # which version of which engine made the call.
        env = analyze(_make_apk(tmp_path), extractors=[_Ok("a")])

        assert env.engine.name == "static"
        assert env.engine.version

    def test_the_envelope_declares_its_schema_version(self, tmp_path: Path) -> None:
        from sephela_static.envelope import ENVELOPE_VERSION

        env = analyze(_make_apk(tmp_path), extractors=[_Ok("a")])

        assert env.envelope_version == ENVELOPE_VERSION

    def test_the_envelope_serialises_to_json(self, tmp_path: Path) -> None:
        # The backend stores model_dump(mode="json") in a JSONB column; a value that
        # will not serialise fails the stage after all the work is done.
        env = analyze(_make_apk(tmp_path))

        payload = env.model_dump(mode="json")

        assert json.loads(json.dumps(payload))["engine"]["name"] == "static"


class TestDefaultChain:
    def test_the_default_chain_is_used_when_none_is_given(self, tmp_path: Path) -> None:
        env = analyze(_make_apk(tmp_path))

        assert "hashes" in env.evidence
        assert "strings" in env.evidence

    def test_an_explicit_empty_chain_is_respected(self, tmp_path: Path) -> None:
        # `extractors=[]` must mean "none", not "fall back to the default" — otherwise
        # a caller cannot narrow the run at all.
        env = analyze(_make_apk(tmp_path), extractors=[])

        assert env.evidence == {}

    def test_every_default_extractor_has_a_unique_name(self) -> None:
        # Evidence is keyed by name, so a duplicate silently overwrites.
        names = [e.name for e in default_extractors()]

        assert len(names) == len(set(names)), names

    def test_no_default_extractor_left_its_placeholder_name(self) -> None:
        # Extractor.name defaults to "extractor"; one that forgot to set it would file
        # its evidence under a key nothing reads.
        for extractor in default_extractors():
            assert extractor.name != "extractor", type(extractor).__name__
