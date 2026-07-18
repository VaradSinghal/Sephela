"""Tests for the control flow analyzer."""

from __future__ import annotations

from pathlib import Path

from sephela_code_intel.analyzers.control_flow import ControlFlowAnalyzer
from sephela_code_intel.base import AnalysisContext
from sephela_code_intel.envelope import Severity


def _make_ctx(tmp_path: Path, filename: str, content: str) -> AnalysisContext:
    sources = tmp_path / "sources"
    sources.mkdir(parents=True, exist_ok=True)
    (sources / filename).write_text(content, encoding="utf-8")
    ctx = AnalysisContext(artifact_dir=tmp_path)
    ctx.shared["class_filter"] = {"developer_source_paths": [filename]}
    return ctx


def test_reflection_chain_detected(tmp_path: Path) -> None:
    """Reflection chain (forName → getMethod → invoke) is detected."""
    code = (
        'Object o = Class.forName("com.hidden.Payload");\n'
        'Method m = o.getClass().getMethod("execute");\n'
        'm.invoke(null);\n'
    )
    ctx = _make_ctx(tmp_path, "Reflector.java", code)
    result = ControlFlowAnalyzer().analyze(ctx)

    patterns = result.evidence["patterns_detected"]
    total = result.evidence["total_matches"]
    assert isinstance(patterns, list)
    assert isinstance(total, int)
    assert "reflection_chain" in patterns
    assert total > 0
    findings = [f for f in result.findings if "reflection_chain" in f.id]
    assert len(findings) > 0
    assert findings[0].severity == Severity.high


def test_dynamic_dex_loading_detected(tmp_path: Path) -> None:
    """Dynamic DEX loading sequence is detected."""
    code = (
        'DexClassLoader loader = new DexClassLoader(path, null, null, cl);\n'
        'Class<?> c = loader.loadClass("com.payload.Main");\n'
    )
    ctx = _make_ctx(tmp_path, "DynLoader.java", code)
    result = ControlFlowAnalyzer().analyze(ctx)

    patterns = result.evidence["patterns_detected"]
    assert isinstance(patterns, list)
    assert "dynamic_dex_loading" in patterns


def test_encoded_string_detected(tmp_path: Path) -> None:
    """Base64 decode + String construction is detected."""
    code = (
        'byte[] decoded = Base64.decode(encoded, 0);\n'
        'String payload = new String(decoded);\n'
    )
    ctx = _make_ctx(tmp_path, "Decoder.java", code)
    result = ControlFlowAnalyzer().analyze(ctx)

    patterns = result.evidence["patterns_detected"]
    assert isinstance(patterns, list)
    assert "encoded_string_construction" in patterns


def test_clean_code_no_patterns(tmp_path: Path) -> None:
    """Normal code produces no control flow findings."""
    code = 'public class Clean {\n    int x = 42;\n    void foo() { bar(); }\n}\n'
    ctx = _make_ctx(tmp_path, "Clean.java", code)
    result = ControlFlowAnalyzer().analyze(ctx)

    assert result.evidence["pattern_count"] == 0
    assert len(result.findings) == 0


def test_multiple_patterns_in_one_file(tmp_path: Path) -> None:
    """Multiple patterns detected in a single file."""
    code = (
        'Class.forName("hidden").getMethod("run").invoke(null);\n'
        'DexClassLoader dl = new DexClassLoader(p, null, null, cl);\n'
        'dl.loadClass("com.x.Y");\n'
        'byte[] d = Base64.decode(s, 0);\n'
        'String r = new String(d);\n'
    )
    ctx = _make_ctx(tmp_path, "MultiEvade.java", code)
    result = ControlFlowAnalyzer().analyze(ctx)

    detected = result.evidence["patterns_detected"]
    total = result.evidence["total_matches"]
    assert isinstance(detected, list)
    assert isinstance(total, int)
    assert len(detected) >= 2
    assert total >= 2
