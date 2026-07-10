"""Pytest configuration and fixtures for Sephela GenAI tests."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock
from typing import Dict, Any

from ai.schemas.base import Finding, Severity, Confidence, EvidenceRef
from ai.schemas.manifest import ManifestAnalysis
from ai.schemas.permission import PermissionAnalysis
from ai.schemas.code import CodeAnalysis
from ai.schemas.network import NetworkAnalysis
from ai.schemas.threat_intel import ThreatIntelAnalysis
from ai.schemas.risk import RiskAnalysis
from ai.schemas.report import ReportGenerationResult
from ai.agents.base import AgentConfig, AgentResult, AgentStatus
from ai.llm.client import LLMConfig, LLMResponse, ModelProvider


@pytest.fixture
def sample_evidence() -> Dict[str, Any]:
    """Sample evidence envelope for testing."""
    return {
        "static_evidence": {
            "manifest": {
                "package_name": "com.example.test",
                "version_name": "1.0.0",
                "version_code": 1,
                "min_sdk": 21,
                "target_sdk": 33,
                "debuggable": True,
                "allow_backup": True,
                "uses_cleartext_traffic": False,
                "main_activity": "com.example.test.MainActivity",
            },
            "permissions": {
                "count": 3,
                "permissions": [
                    "android.permission.INTERNET",
                    "android.permission.BIND_ACCESSIBILITY_SERVICE",
                    "android.permission.SYSTEM_ALERT_WINDOW",
                ],
            },
            "components": {
                "counts": {"activities": 1, "services": 1, "receivers": 0, "providers": 0},
                "activities": ["com.example.test.MainActivity"],
                "services": ["com.example.test.AccessibilityService"],
                "receivers": [],
                "providers": [],
                "intent_filters": {
                    "com.example.test.MainActivity": [{"action": "android.intent.action.MAIN"}]
                },
            },
            "certificate": {
                "certificates": [
                    {"subject": "CN=Test", "issuer": "CN=Test", "sha256": "abc123", "self_signed": True}
                ]
            },
            "network": {
                "domains": ["example.com", "malicious.tk", "c2.badguy.net"],
                "ips": ["1.2.3.4", "192.168.1.1"],
                "urls": ["https://example.com/api", "http://malicious.tk/c2"]
            },
            "strings": {
                "count": 100,
                "high_entropy_count": 5,
                "suspicious": ["http://c2.badguy.net", "malicious_payload", "keylogger"]
            },
            "hashes": {
                "sha256": "a" * 64,
                "sha1": "b" * 40,
                "md5": "c" * 32,
                "ssdeep": "ssdeep_hash",
                "tlsh": "tlsh_hash"
            },
        },
        "code_intel": {
            "summarizer": {
                "code_summary": {
                    "total_classes": 50,
                    "total_methods": 200,
                    "app_classes": 20,
                    "app_methods": 80,
                    "entry_points": ["MainActivity", "AccessibilityService"],
                    "network_apis": ["OkHttpClient", "Retrofit"],
                    "crypto_apis": ["Cipher", "SecretKeySpec"],
                    "reflection_usage": ["Class.forName", "Method.invoke"],
                    "native_libs": ["libnative.so"],
                    "string_obfuscation": True,
                    "anti_analysis": ["emulator_check", "debugger_check"],
                }
            },
            "api_usage": {
                "dangerous_apis": ["Landroid/view/WindowManager;->addView", "Landroid/accessibilityservice/AccessibilityService;->onAccessibilityEvent"],
                "call_sites": [
                    {"method": "MainActivity.onCreate", "api": "WindowManager.addView", "line": 42},
                    {"method": "AccessibilityService.onAccessibilityEvent", "api": "AccessibilityService.onAccessibilityEvent", "line": 15}
                ],
                "reflection_usage": ["Class.forName", "Method.invoke"],
                "dynamic_loading": ["DexClassLoader"],
                "native_libraries": ["libnative.so"],
            },
            "call_graph": {
                "nodes": ["MainActivity.onCreate", "AccessibilityService.onAccessibilityEvent"],
                "edges": [],
                "entry_points": ["MainActivity.onCreate"],
                "sinks": ["WindowManager.addView"],
            },
            "control_flow": {
                "anomalies": [
                    {"method": "MalwareClass.evilMethod", "type": "obfuscated", "description": "String decryption loop"}
                ]
            },
            "class_filter": {
                "app_class_count": 20,
                "framework_class_count": 30,
                "library_class_count": 0,
            },
        },
    }


@pytest.fixture
def mock_llm_client():
    """Mock LLM client for testing."""
    client = AsyncMock()
    client.complete = AsyncMock(return_value=LLMResponse(
        content='{"test": "output"}',
        model="claude-3-5-sonnet-20241022",
        provider=ModelProvider.ANTHROPIC,
        tokens_used=100,
        latency_ms=500,
        finish_reason="stop",
    ))
    client.stream_complete = AsyncMock()
    client.close = AsyncMock()
    return client


@pytest.fixture
def sample_findings() -> list:
    """Sample findings for testing."""
    return [
        Finding(
            id="test_1",
            type="permission",
            severity=Severity.critical,
            confidence=Confidence.very_high,
            title="Critical permission",
            description="Test critical finding",
            mitre_techniques=["T1417.001"],
            owasp_mobile=["M1"],
        ),
        Finding(
            id="test_2",
            type="network",
            severity=Severity.high,
            confidence=Confidence.high,
            title="Suspicious domain",
            description="Test high finding",
            mitre_techniques=["T1071.001"],
            owasp_mobile=["M3"],
        ),
    ]


@pytest.fixture
def manifest_analysis_output() -> ManifestAnalysis:
    """Sample manifest analysis output."""
    return ManifestAnalysis(
        package_name="com.example.test",
        version_name="1.0.0",
        version_code=1,
        min_sdk=21,
        target_sdk=33,
        debuggable=True,
        allow_backup=True,
        exported_component_count=2,
        dangerous_permission_count=2,
        critical_findings=1,
        high_findings=1,
        medium_findings=0,
        low_findings=0,
        info_findings=0,
    )


@pytest.fixture
def permission_analysis_output() -> PermissionAnalysis:
    """Sample permission analysis output."""
    return PermissionAnalysis(
        total_permissions=7,
        critical_count=1,
        high_count=2,
        medium_count=0,
        low_count=0,
        financial_risk_score=0.9,
    )


@pytest.fixture
def code_analysis_output() -> CodeAnalysis:
    """Sample code analysis output."""
    return CodeAnalysis(
        summary={},
        findings=[],
    )


@pytest.fixture
def network_analysis_output() -> NetworkAnalysis:
    """Sample network analysis output."""
    return NetworkAnalysis(
        domains=["example.com", "malicious.tk"],
        ips=["1.2.3.4"],
        findings=[],
        malicious_domain_count=1,
        critical_findings=0,
        high_findings=1,
    )


@pytest.fixture
def threat_intel_output() -> ThreatIntelAnalysis:
    """Sample threat intel output."""
    return ThreatIntelAnalysis(
        total_ioc_matches=5,
        family_attributions=1,
        critical_findings=1,
        high_findings=0,
    )


@pytest.fixture
def risk_analysis_output() -> RiskAnalysis:
    """Sample risk analysis output."""
    return RiskAnalysis(
        score=85.0,
        tier="malicious",
        confidence=0.9,
        breakdown={"factors": []},
        primary_category="banking_trojan",
        static_score=85.0,
        permission_score=90.0,
    )


@pytest.fixture
def report_generation_result() -> ReportGenerationResult:
    """Sample report generation result."""
    return ReportGenerationResult(
        report=None,
        generation_time_ms=100,
    )


@pytest.fixture
def agent_config() -> AgentConfig:
    """Sample agent configuration."""
    return AgentConfig(
        name="test_agent",
        model="claude-3-5-sonnet-20241022",
        temperature=0.1,
        max_tokens=4096,
        timeout_seconds=30,
    )


@pytest.fixture
def agent_result(agent_config) -> AgentResult:
    """Sample agent result."""
    return AgentResult(
        agent_name="test_agent",
        status=AgentStatus.completed,
        output=None,
        findings=[],
        execution_time_ms=1000,
        tokens_used=500,
        model_name="claude-3-5-sonnet-20241022",
    )


@pytest.fixture
def llm_config() -> LLMConfig:
    """Sample LLM configuration."""
    return LLMConfig(
        provider=ModelProvider.ANTHROPIC,
        model="claude-3-5-sonnet-20241022",
        api_key="test_key",
        temperature=0.1,
        max_tokens=4096,
    )


# Async test support
pytest.mark.asyncio = pytest.mark.asyncio