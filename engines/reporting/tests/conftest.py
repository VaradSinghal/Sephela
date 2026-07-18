"""Shared test fixtures for the reporting engine test suite.

Provides a realistic, synthetic ``AnalysisReport`` dict that exercises
all renderers with edge cases (unicode, empty lists, long descriptions,
multiple findings across severities).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest


def _make_report_data(**overrides: Any) -> dict[str, Any]:
    """Build a synthetic AnalysisReport dict.

    Args:
        **overrides: Override any top-level keys.

    Returns:
        A dict suitable for ``AnalysisReport.model_validate()``.
    """
    base: dict[str, Any] = {
        "report_id": "rpt_test_001",
        "job_id": "job_abc123",
        "sample_sha256": "a" * 64,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": "Sephela Test Suite",
        "version": "1.0",
        "format": "json",
        "classification": "TLP:AMBER",
        "executive_summary": {
            "overview": "This APK exhibits characteristics of a banking trojan targeting SMS interception and overlay attacks.",
            "risk_score": 92.5,
            "risk_tier": "critical",
            "primary_category": "Banking Trojan",
            "key_findings": [
                "Sends SMS to premium-rate numbers",
                "Uses accessibility services for overlay attacks",
                "Communicates with known C2 infrastructure",
                "Contains obfuscated payload with dynamic class loading",
            ],
            "business_impact": "High risk of financial fraud through intercepted banking credentials and unauthorized fund transfers.",
            "recommended_actions": [
                "Block sample SHA256 at endpoint protection",
                "Add C2 domains to network deny-list",
                "Issue fraud alert for affected customers",
                "Review SMS-based 2FA for affected banking services",
            ],
            "one_page_summary": "",
        },
        "technical_details": {
            "sample_info": {
                "sha256": "a" * 64,
                "sha1": "b" * 40,
                "md5": "c" * 32,
                "file_size": 2_500_000,
                "package_name": "com.malicious.banking.app",
                "min_sdk": 21,
                "target_sdk": 33,
            },
            "static_analysis": {
                "permissions_count": 24,
                "dangerous_permissions": [
                    "android.permission.SEND_SMS",
                    "android.permission.READ_SMS",
                    "android.permission.SYSTEM_ALERT_WINDOW",
                ],
                "receivers_count": 5,
                "services_count": 3,
            },
            "code_analysis": {
                "total_classes": 450,
                "developer_classes": 120,
                "obfuscation_score": 0.78,
            },
            "network_analysis": {
                "domains_contacted": ["evil.example.com", "c2.malware.net"],
                "ip_addresses": ["198.51.100.42"],
            },
            "threat_intel": {
                "malware_family": "Cerberus",
                "first_seen": "2025-01-15",
            },
            "ai_reasoning": {
                "agent_consensus": "All agents agree this is a banking trojan.",
            },
        },
        "evidence_catalog": {
            "static_evidence": [{"extractor": "manifest", "key": "permissions"}],
            "dynamic_evidence": [],
            "network_captures": [],
            "decompiled_sources": [],
            "extracted_strings": ["http://evil.example.com/gate", "SMS_INTERCEPT"],
            "ioc_list": [
                {"type": "domain", "value": "evil.example.com"},
                {"type": "ip", "value": "198.51.100.42"},
                {"type": "sha256", "value": "a" * 64},
            ],
        },
        "compliance_mapping": {
            "mitre_attack": {
                "techniques": ["T1636.004", "T1517", "T1411"],
            },
            "owasp_mobile": {
                "categories": ["M1", "M3", "M7"],
            },
            "nist_csf": {
                "functions": ["Identify", "Protect", "Detect"],
            },
            "iso_27001": {},
            "pci_dss": {},
        },
        "sections": [
            {
                "section_id": "exec_summary",
                "title": "Executive Summary",
                "content": "See executive_summary.",
                "order": 1,
                "subsections": [],
                "findings_refs": [],
                "evidence_refs": [],
            },
        ],
        "findings": [
            {
                "id": "perm_sms_001",
                "type": "permission_risk",
                "severity": "critical",
                "confidence": "high",
                "title": "SMS Interception Permission",
                "description": "The application requests READ_SMS and SEND_SMS permissions, enabling full SMS interception for 2FA bypass.",
                "evidence_refs": [
                    {
                        "extractor": "manifest",
                        "path": "permissions[0]",
                        "snippet": "android.permission.READ_SMS",
                    }
                ],
                "mitre_techniques": ["T1636.004"],
                "owasp_mobile": ["M1"],
                "metadata": {},
            },
            {
                "id": "net_c2_001",
                "type": "network_c2",
                "severity": "high",
                "confidence": "high",
                "title": "C2 Communication Detected",
                "description": "The application communicates with evil.example.com, a known command-and-control server associated with the Cerberus malware family.",
                "evidence_refs": [
                    {
                        "extractor": "network",
                        "path": "domains[0]",
                        "snippet": "evil.example.com",
                    }
                ],
                "mitre_techniques": ["T1071"],
                "owasp_mobile": ["M3"],
                "metadata": {},
            },
            {
                "id": "code_obf_001",
                "type": "obfuscation",
                "severity": "medium",
                "confidence": "medium",
                "title": "High Obfuscation Score",
                "description": "Developer code exhibits 78% name mangling, indicating deliberate obfuscation to hinder analysis.",
                "evidence_refs": [],
                "mitre_techniques": ["T1027"],
                "owasp_mobile": [],
                "metadata": {},
            },
            {
                "id": "info_meta_001",
                "type": "metadata",
                "severity": "info",
                "confidence": "very_high",
                "title": "Package Metadata",
                "description": "Package com.malicious.banking.app targets SDK 33 with min SDK 21.",
                "evidence_refs": [],
                "mitre_techniques": [],
                "owasp_mobile": [],
                "metadata": {},
            },
        ],
        "distribution_restrictions": [],
    }
    base.update(overrides)
    return base


@pytest.fixture()
def sample_report_data() -> dict[str, Any]:
    """Fixture providing a realistic synthetic report dict."""
    return _make_report_data()


@pytest.fixture()
def minimal_report_data() -> dict[str, Any]:
    """Fixture providing a minimal report with no findings or evidence."""
    return _make_report_data(
        report_id="rpt_minimal",
        executive_summary={
            "overview": "No threats detected.",
            "risk_score": 5.0,
            "risk_tier": "benign",
            "key_findings": [],
            "business_impact": "",
            "recommended_actions": [],
            "one_page_summary": "",
        },
        findings=[],
        evidence_catalog={
            "static_evidence": [],
            "dynamic_evidence": [],
            "network_captures": [],
            "decompiled_sources": [],
            "extracted_strings": [],
            "ioc_list": [],
        },
    )


@pytest.fixture()
def unicode_report_data() -> dict[str, Any]:
    """Fixture with unicode content to test encoding correctness."""
    return _make_report_data(
        report_id="rpt_unicode",
        executive_summary={
            "overview": "样本分析显示恶意行为 — trojan détecté avec des caractères spéciaux: ñ, ü, ö, 日本語テスト",
            "risk_score": 75.0,
            "risk_tier": "malicious",
            "key_findings": ["Обнаружен троян", "マルウェア検出"],
            "business_impact": "",
            "recommended_actions": [],
            "one_page_summary": "",
        },
        findings=[],
    )
