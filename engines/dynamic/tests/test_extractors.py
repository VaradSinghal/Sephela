"""Tests for individual dynamic analysis extractors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sephela_dynamic.base import ArtifactsContext
from sephela_dynamic.envelope import FindingType, Severity
from sephela_dynamic.extractors.frida import FridaExtractor
from sephela_dynamic.extractors.network import NetworkExtractor
from sephela_dynamic.extractors.logcat import LogcatExtractor


# ---------------------------------------------------------------------------
# Frida Extractor
# ---------------------------------------------------------------------------

class TestFridaExtractor:
    """Tests for ``FridaExtractor``."""

    def test_banking_trojan_hooks(self, banking_trojan_artifacts: Path) -> None:
        """Correctly parses and categorises banking trojan hooks."""
        ctx = ArtifactsContext(artifacts_dir=banking_trojan_artifacts)
        result = FridaExtractor().extract(ctx)

        evidence = result.evidence
        assert isinstance(evidence, dict)
        assert evidence["total_hooks"] == 8
        assert isinstance(evidence["hook_type_counts"], dict)
        assert evidence["hook_type_counts"]["crypto"] == 2
        assert evidence["hook_type_counts"]["sms"] == 1

    def test_compound_patterns(self, banking_trojan_artifacts: Path) -> None:
        """Compound patterns are detected."""
        ctx = ArtifactsContext(artifacts_dir=banking_trojan_artifacts)
        result = FridaExtractor().extract(ctx)

        finding_ids = {f.id for f in result.findings}
        assert "dyn_frida_staged_payload" in finding_ids
        assert "dyn_frida_encrypted_sms" in finding_ids
        assert "dyn_frida_overlay_prep" in finding_ids

    def test_clean_app_no_findings(self, clean_app_artifacts: Path) -> None:
        """Clean app produces no Frida findings."""
        ctx = ArtifactsContext(artifacts_dir=clean_app_artifacts)
        result = FridaExtractor().extract(ctx)
        assert len(result.findings) == 0
        assert result.evidence["total_hooks"] == 0

    def test_missing_trace(self, tmp_path: Path) -> None:
        """Missing frida_trace.json returns error evidence."""
        ctx = ArtifactsContext(artifacts_dir=tmp_path)
        result = FridaExtractor().extract(ctx)
        assert "error" in result.evidence

    def test_mitre_mappings(self, banking_trojan_artifacts: Path) -> None:
        """Findings carry MITRE ATT&CK technique IDs."""
        ctx = ArtifactsContext(artifacts_dir=banking_trojan_artifacts)
        result = FridaExtractor().extract(ctx)
        mitre_ids = set()
        for f in result.findings:
            mitre_ids.update(f.mappings.mitre)
        assert "T1636.004" in mitre_ids  # SMS
        assert "T1620" in mitre_ids  # DEX loading


# ---------------------------------------------------------------------------
# Network Extractor
# ---------------------------------------------------------------------------

class TestNetworkExtractor:
    """Tests for ``NetworkExtractor``."""

    def test_cleartext_http_detected(self, banking_trojan_artifacts: Path) -> None:
        """Cleartext HTTP requests produce high-severity findings."""
        ctx = ArtifactsContext(artifacts_dir=banking_trojan_artifacts)
        result = NetworkExtractor().extract(ctx)

        cleartext = [f for f in result.findings if "cleartext" in f.id]
        assert len(cleartext) == 1
        assert cleartext[0].severity == Severity.high

    def test_suspicious_port_detected(self, banking_trojan_artifacts: Path) -> None:
        """Connections to suspicious ports (4444, 8080) are flagged."""
        ctx = ArtifactsContext(artifacts_dir=banking_trojan_artifacts)
        result = NetworkExtractor().extract(ctx)

        port_findings = [f for f in result.findings if "port" in f.id]
        assert len(port_findings) >= 2  # 8080 + 4444
        ports_flagged = {int(f.id.split("_")[3]) for f in port_findings}
        assert 4444 in ports_flagged
        assert 8080 in ports_flagged

    def test_self_signed_cert(self, banking_trojan_artifacts: Path) -> None:
        """Self-signed TLS certificates are flagged."""
        ctx = ArtifactsContext(artifacts_dir=banking_trojan_artifacts)
        result = NetworkExtractor().extract(ctx)

        cert_findings = [f for f in result.findings if "selfsigned" in f.id]
        assert len(cert_findings) == 1
        assert "evil.example.com" in cert_findings[0].detail

    def test_evidence_structure(self, banking_trojan_artifacts: Path) -> None:
        """Evidence contains expected network metadata."""
        ctx = ArtifactsContext(artifacts_dir=banking_trojan_artifacts)
        result = NetworkExtractor().extract(ctx)

        evidence = result.evidence
        assert isinstance(evidence, dict)
        assert isinstance(evidence["unique_dst_ips"], list)
        assert isinstance(evidence["unique_dst_domains"], list)
        assert "evil.example.com" in evidence["unique_dst_domains"]
        assert evidence["cleartext_http_count"] == 1

    def test_clean_app_no_network_findings(self, clean_app_artifacts: Path) -> None:
        """Clean app with no network activity produces no findings."""
        ctx = ArtifactsContext(artifacts_dir=clean_app_artifacts)
        result = NetworkExtractor().extract(ctx)
        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Logcat Extractor
# ---------------------------------------------------------------------------

class TestLogcatExtractor:
    """Tests for ``LogcatExtractor``."""

    def test_sms_broadcast_detected(self, banking_trojan_artifacts: Path) -> None:
        """SMS_RECEIVED broadcast is flagged as critical."""
        ctx = ArtifactsContext(artifacts_dir=banking_trojan_artifacts)
        result = LogcatExtractor().extract(ctx)

        sms = [f for f in result.findings if "sms_broadcast" in f.id]
        assert len(sms) == 1
        assert sms[0].severity == Severity.critical

    def test_webview_detected(self, banking_trojan_artifacts: Path) -> None:
        """WebView.loadUrl is detected as potential phishing overlay."""
        ctx = ArtifactsContext(artifacts_dir=banking_trojan_artifacts)
        result = LogcatExtractor().extract(ctx)

        webview = [f for f in result.findings if "webview_load" in f.id]
        assert len(webview) == 1

    def test_dex_loading_in_logcat(self, banking_trojan_artifacts: Path) -> None:
        """DexClassLoader in logcat is flagged."""
        ctx = ArtifactsContext(artifacts_dir=banking_trojan_artifacts)
        result = LogcatExtractor().extract(ctx)

        dex = [f for f in result.findings if "dex_load_log" in f.id]
        assert len(dex) == 1
        assert dex[0].severity == Severity.critical

    def test_crash_detection(self, banking_trojan_artifacts: Path) -> None:
        """FATAL EXCEPTION is detected as a crash."""
        ctx = ArtifactsContext(artifacts_dir=banking_trojan_artifacts)
        result = LogcatExtractor().extract(ctx)

        crashes = [f for f in result.findings if "crashes" in f.id]
        assert len(crashes) == 1

    def test_evidence_structure(self, banking_trojan_artifacts: Path) -> None:
        """Evidence contains expected log statistics."""
        ctx = ArtifactsContext(artifacts_dir=banking_trojan_artifacts)
        result = LogcatExtractor().extract(ctx)

        evidence = result.evidence
        assert isinstance(evidence, dict)
        assert evidence["total_lines"] == 6
        assert isinstance(evidence["pattern_matches"], dict)
        assert evidence["crash_count"] == 1

    def test_clean_app_no_logcat_findings(self, clean_app_artifacts: Path) -> None:
        """Clean app logcat produces no suspicious findings."""
        ctx = ArtifactsContext(artifacts_dir=clean_app_artifacts)
        result = LogcatExtractor().extract(ctx)
        assert len(result.findings) == 0

    def test_text_logcat_fallback(self, tmp_path: Path) -> None:
        """Falls back to plain-text logcat parsing."""
        logcat_text = (
            "01-15 12:00:00.000  100  100 I ActivityManager: Starting app\n"
            "01-15 12:00:01.000  200  200 W SmsReceiver: android.provider.Telephony.SMS_RECEIVED\n"
            "01-15 12:00:02.000  200  200 E AndroidRuntime: FATAL EXCEPTION: main\n"
        )
        (tmp_path / "logcat.txt").write_text(logcat_text, encoding="utf-8")

        ctx = ArtifactsContext(artifacts_dir=tmp_path)
        result = LogcatExtractor().extract(ctx)

        # Should detect SMS_RECEIVED and FATAL EXCEPTION
        assert len(result.findings) >= 2
        evidence = result.evidence
        assert isinstance(evidence, dict)
        assert evidence["total_lines"] == 3
