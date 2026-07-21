"""Tests for the dynamic analysis pipeline orchestrator."""

from __future__ import annotations

from pathlib import Path

import pytest

from sephela_dynamic.envelope import Status
from sephela_dynamic.pipeline import analyze


class TestPipelineBankingTrojan:
    """Tests with banking trojan artifacts (high-threat)."""

    def test_pipeline_completes(self, banking_trojan_artifacts: Path) -> None:
        """Pipeline runs all extractors successfully."""
        envelope = analyze(banking_trojan_artifacts, job_id="test-001")
        assert envelope.status == Status.ok
        assert len(envelope.errors) == 0

    def test_metadata_loaded(self, banking_trojan_artifacts: Path) -> None:
        """Sandbox metadata is loaded into envelope."""
        envelope = analyze(banking_trojan_artifacts, job_id="test-001")
        assert envelope.apk_sha256 == "a" * 64
        assert envelope.sandbox_duration_ms == 120000
        meta = envelope.evidence.get("sandbox_metadata")
        assert isinstance(meta, dict)
        assert meta["sandbox_id"] == "sandbox-test-001"
        assert meta["network_isolated"] is True

    def test_all_extractors_contributed(self, banking_trojan_artifacts: Path) -> None:
        """All three extractors produce evidence."""
        envelope = analyze(banking_trojan_artifacts, job_id="test-001")
        assert "frida" in envelope.evidence
        assert "network" in envelope.evidence
        assert "logcat" in envelope.evidence

    def test_findings_generated(self, banking_trojan_artifacts: Path) -> None:
        """Multiple findings are generated from the banking trojan."""
        envelope = analyze(banking_trojan_artifacts, job_id="test-001")
        assert len(envelope.findings) > 5  # compound patterns + individual hooks

    def test_critical_findings_present(self, banking_trojan_artifacts: Path) -> None:
        """Critical-severity findings exist for SMS and DEX loading."""
        envelope = analyze(banking_trojan_artifacts, job_id="test-001")
        from sephela_dynamic.envelope import Severity
        critical = [f for f in envelope.findings if f.severity == Severity.critical]
        assert len(critical) >= 3  # SMS, DEX, accessibility, compound patterns

    def test_compound_patterns_detected(self, banking_trojan_artifacts: Path) -> None:
        """Compound patterns (staged payload, encrypted SMS) are detected."""
        envelope = analyze(banking_trojan_artifacts, job_id="test-001")
        finding_ids = {f.id for f in envelope.findings}
        assert "dyn_frida_staged_payload" in finding_ids
        assert "dyn_frida_encrypted_sms" in finding_ids
        assert "dyn_frida_overlay_prep" in finding_ids

    def test_envelope_version(self, banking_trojan_artifacts: Path) -> None:
        """Envelope version is set correctly."""
        envelope = analyze(banking_trojan_artifacts, job_id="test-001")
        assert envelope.envelope_version == "1.0"
        assert envelope.engine.name == "dynamic"
        assert envelope.engine.version == "1.0.0"


class TestPipelineCleanApp:
    """Tests with clean app artifacts (no threats)."""

    def test_clean_app_no_findings(self, clean_app_artifacts: Path) -> None:
        """Clean app produces zero findings."""
        envelope = analyze(clean_app_artifacts, job_id="test-002")
        assert envelope.status == Status.ok
        assert len(envelope.findings) == 0

    def test_clean_app_metadata(self, clean_app_artifacts: Path) -> None:
        """Clean app metadata is loaded."""
        envelope = analyze(clean_app_artifacts, job_id="test-002")
        assert envelope.apk_sha256 == "b" * 64


class TestPipelineMissingArtifacts:
    """Tests with missing artifact files."""

    def test_graceful_degradation(self, missing_artifacts: Path) -> None:
        """Missing artifacts produce partial status, not crash."""
        envelope = analyze(missing_artifacts, job_id="test-003")
        assert envelope.status == Status.partial
        assert len(envelope.errors) > 0

    def test_metadata_still_loaded(self, missing_artifacts: Path) -> None:
        """Metadata is loaded even when extractors can't run."""
        envelope = analyze(missing_artifacts, job_id="test-003")
        assert envelope.apk_sha256 == "c" * 64

    def test_nonexistent_dir_raises(self) -> None:
        """Non-existent directory raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            analyze("/nonexistent/path", job_id="test-fail")
