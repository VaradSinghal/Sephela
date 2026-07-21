"""End-to-End integration test for the Sephela Analysis Pipeline."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import BaseModel

from backend.app.core.integration import run_e2e_pipeline
from ai.agents.base import AgentResult, AgentStatus


class MockAgentOutput(BaseModel):
    """Dummy output model for mocked AI agents."""
    summary: str = "Mocked AI reasoning summary."


@pytest.fixture
def mock_ai_agents():
    """Mock the execute method of BaseAgent to bypass actual LLM calls."""
    mock_result = AgentResult(
        agent_name="mock_agent",
        status=AgentStatus.completed,
        output=MockAgentOutput(),
        findings=[
            {
                "id": "ai_mock_finding_1",
                "type": "malicious_behavior",
                "severity": "high",
                "confidence": "high",
                "title": "Mock finding",
                "description": "Mock description",
                "detail": "AI detected anomalous behavior pattern in code.",
                "provenance": {"extractor": "ai_mock_agent"},
                "mappings": {"mitre": ["T1204"], "owasp_mobile": []}
            }
        ]
    )
    
    with patch("ai.agents.base.BaseAgent.execute", new_callable=AsyncMock) as mock_execute:
        mock_execute.return_value = mock_result
        yield mock_execute


@pytest.mark.asyncio
async def test_end_to_end_pipeline(
    tmp_path: Path, 
    banking_trojan_artifacts: Path,
    mock_ai_agents
) -> None:
    """Verify that all engines can execute and pass data sequentially.

    This test runs the Static, Code Intel, Dynamic (with golden artifacts),
    AI (mocked), Scoring, and Reporting engines.
    """
    # 1. Create a dummy APK for the static engine to parse.
    # Since we need a valid APK to not crash androguard completely,
    # we'll patch the static engine's core extraction for this test if needed,
    # or just use a minimal valid structure.
    # Actually, the static engine pipeline handles exceptions gracefully (isolates them).
    # We can just provide a dummy file and it will degrade to partial.
    dummy_apk = tmp_path / "dummy.apk"
    dummy_apk.write_bytes(b"PK\x03\x04")  # minimal zip header

    # Ensure output directory for reports exists
    (tmp_path / "reports").mkdir(exist_ok=True)

    # 2. Execute the E2E pipeline
    report, render_results = await run_e2e_pipeline(
        apk_path=dummy_apk,
        dynamic_artifacts_dir=banking_trojan_artifacts,
        job_id="e2e-test-123",
        mock_ai=True
    )

    # 3. Assertions
    # Check that report was generated successfully
    assert report.job_id == "e2e-test-123"
    assert report.executive_summary is not None
    
    # Check that dynamic findings propagated all the way through
    finding_ids = {f.id for f in report.findings}
    assert "dyn_frida_staged_payload" in finding_ids, "Dynamic findings were dropped"
    
    # Check that AI findings propagated all the way through
    assert "ai_mock_finding_1" in finding_ids, "AI findings were dropped"

    # Check that Risk Scoring engine evaluated the findings
    # We just ensure the score is calculated correctly from the mock inputs
    assert report.executive_summary.risk_score > 0
    assert report.executive_summary.risk_tier in ("benign", "suspicious", "malicious", "critical")

    # Check that Reporting Engine generated the artifacts
    assert "json" in render_results
    assert "markdown" in render_results
    
    # Verify the generated JSON report
    json_path = Path(render_results["json"].filename)
    assert json_path.exists()
    assert json_path.stat().st_size > 0
    
    # Verify the generated HTML report
    html_path = Path(render_results["html"])
    assert html_path.exists()
    assert b"e2e-test-123" in html_path.read_bytes()
