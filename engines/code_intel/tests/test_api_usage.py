"""Tests for the API usage analyzer."""

from __future__ import annotations

from pathlib import Path

from sephela_code_intel.analyzers.api_usage import ApiUsageAnalyzer
from sephela_code_intel.base import AnalysisContext
from sephela_code_intel.envelope import FindingType, Severity


def _make_ctx_with_source(tmp_path: Path, filename: str, content: str) -> AnalysisContext:
    """Create an AnalysisContext with a single Java source file."""
    sources = tmp_path / "sources"
    sources.mkdir(parents=True, exist_ok=True)
    (sources / filename).write_text(content, encoding="utf-8")
    ctx = AnalysisContext(artifact_dir=tmp_path)
    # Pre-populate class filter output to mark all files as developer.
    ctx.shared["class_filter"] = {
        "developer_source_paths": [filename],
    }
    return ctx


def test_sms_api_detected(tmp_path: Path) -> None:
    """SmsManager usage produces high-severity findings."""
    ctx = _make_ctx_with_source(
        tmp_path,
        "SmsHijacker.java",
        'SmsManager.getDefault().sendTextMessage("1234", null, "stolen", null, null);',
    )
    result = ApiUsageAnalyzer().analyze(ctx)

    categories = result.evidence["categories_detected"]
    total = result.evidence["total_findings"]
    assert isinstance(categories, list)
    assert isinstance(total, int)
    assert "sms_access" in categories
    assert total > 0
    sms_findings = [f for f in result.findings if "sms_access" in f.id]
    assert len(sms_findings) > 0
    assert sms_findings[0].severity == Severity.high
    assert "T1636.004" in sms_findings[0].mappings.mitre


def test_reflection_detected(tmp_path: Path) -> None:
    """Reflection API usage is detected."""
    ctx = _make_ctx_with_source(
        tmp_path,
        "Reflector.java",
        'Class.forName("com.hidden.Payload").getMethod("run").invoke(null);',
    )
    result = ApiUsageAnalyzer().analyze(ctx)
    categories = result.evidence["categories_detected"]
    assert isinstance(categories, list)
    assert "reflection" in categories


def test_dynamic_loading_detected(tmp_path: Path) -> None:
    """Dynamic class loading is detected with high severity."""
    ctx = _make_ctx_with_source(
        tmp_path,
        "DynLoader.java",
        'new DexClassLoader(path, null, null, cl).loadClass("Payload");',
    )
    result = ApiUsageAnalyzer().analyze(ctx)
    categories = result.evidence["categories_detected"]
    assert isinstance(categories, list)
    assert "dynamic_loading" in categories
    dyn_findings = [f for f in result.findings if "dynamic_loading" in f.id]
    assert len(dyn_findings) > 0
    assert dyn_findings[0].severity == Severity.high


def test_clean_code_no_findings(tmp_path: Path) -> None:
    """Normal code without suspicious APIs produces no findings."""
    ctx = _make_ctx_with_source(
        tmp_path,
        "CleanActivity.java",
        'public class CleanActivity {\n    int x = 42;\n    String name = "hello";\n}\n',
    )
    result = ApiUsageAnalyzer().analyze(ctx)
    assert result.evidence["total_findings"] == 0
    assert len(result.findings) == 0


def test_findings_have_provenance(tmp_path: Path) -> None:
    """Every finding carries source location provenance."""
    ctx = _make_ctx_with_source(
        tmp_path,
        "Evil.java",
        'line1\nline2\nSmsManager.getDefault();\nline4\n',
    )
    result = ApiUsageAnalyzer().analyze(ctx)
    for finding in result.findings:
        assert finding.type == FindingType.api
        assert finding.provenance.extractor == "api_usage"
        assert finding.provenance.locator is not None
        assert "Evil.java" in finding.provenance.locator
