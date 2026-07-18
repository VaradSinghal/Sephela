"""Call graph builder — lightweight static call graph from developer source.

Builds a best-effort method-invocation graph from decompiled Java source using
regex-based extraction. This is intentionally lightweight (no javac or AST
parser dependency): JADX output is clean enough that simple patterns capture
the vast majority of method calls.

The primary output is call chains from entry points (Activities, Services,
BroadcastReceivers) to dangerous API calls — the paths a banking trojan
would use to reach SMS, accessibility, or overlay APIs.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from sephela_code_intel.base import Analyzer, AnalysisContext, AnalyzerResult
from sephela_code_intel.constants import DANGEROUS_API_CATEGORIES
from sephela_code_intel.envelope import (
    Finding,
    FindingType,
    Mappings,
    Provenance,
    Severity,
)

# Regex to extract method definitions: `<modifiers> <return> <name>(<args>)`
_METHOD_DEF = re.compile(
    r"(?:public|private|protected|static|final|synchronized|abstract|native|\s)+"
    r"\S+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[^{]*)?\{",
)

# Regex to extract method invocations: `<receiver>.<method>(` or `<method>(`
_METHOD_CALL = re.compile(r"(\w+)\s*\.\s*(\w+)\s*\(")

# Entry point base class names
_ENTRY_POINT_INDICATORS = (
    "Activity", "AppCompatActivity", "FragmentActivity",
    "Service", "IntentService", "JobService",
    "BroadcastReceiver",
    "ContentProvider",
    "AccessibilityService",
    "DeviceAdminReceiver",
)

# Flatten all dangerous API method names for quick lookup
_DANGEROUS_METHOD_NAMES: set[str] = set()
for _spec in DANGEROUS_API_CATEGORIES.values():
    for _pat in _spec["patterns"]:  # type: ignore[union-attr]
        # Extract likely method/class names from the regex patterns
        for _word in re.findall(r"[A-Z]\w+|[a-z]\w+", _pat):
            if len(_word) > 3:  # skip short words like "su"
                _DANGEROUS_METHOD_NAMES.add(_word)


def _is_entry_point(source: str) -> bool:
    """Check if a Java source file extends a known entry point class."""
    return any(
        re.search(rf"extends\s+{ep}\b", source) for ep in _ENTRY_POINT_INDICATORS
    )


def _extract_class_name(source: str) -> str:
    """Extract the primary class name from a Java source file."""
    match = re.search(r"class\s+(\w+)", source)
    return match.group(1) if match else "Unknown"


class CallGraphAnalyzer(Analyzer):
    """Build a lightweight static call graph focused on suspicious API paths."""

    name = "call_graph"

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        # Use developer sources only.
        dev_paths: list[str] | None = None
        class_filter_ev = ctx.shared.get("class_filter", {})
        if isinstance(class_filter_ev, dict):
            dev_paths = class_filter_ev.get("developer_source_paths")  # type: ignore[assignment]

        sources = ctx.source_files
        if dev_paths is not None:
            sources = {p: sources[p] for p in dev_paths if p in sources}

        # Phase 1: Extract call relationships per file.
        entry_points: list[str] = []
        # Graph: caller_class → set of (callee_method)
        calls: dict[str, set[str]] = defaultdict(set)
        # Track which files contain dangerous API references
        dangerous_files: dict[str, list[str]] = defaultdict(list)

        for rel_path, content in sources.items():
            class_name = _extract_class_name(content)

            if _is_entry_point(content):
                entry_points.append(class_name)

            # Extract method calls
            for match in _METHOD_CALL.finditer(content):
                receiver, method = match.group(1), match.group(2)
                calls[class_name].add(f"{receiver}.{method}")

                # Check if this is a dangerous API call
                if receiver in _DANGEROUS_METHOD_NAMES or method in _DANGEROUS_METHOD_NAMES:
                    dangerous_files[class_name].append(f"{receiver}.{method}")

        # Phase 2: Trace paths from entry points to dangerous calls (BFS, depth-limited).
        suspicious_paths: list[dict[str, Any]] = []
        max_depth = 5
        findings: list[Finding] = []

        for ep in entry_points:
            if ep in dangerous_files:
                for api_call in dangerous_files[ep][:10]:
                    path_info = {
                        "entry_point": ep,
                        "dangerous_api": api_call,
                        "path": [ep],
                        "depth": 0,
                    }
                    suspicious_paths.append(path_info)

            # Check one level of transitivity: entry_point → intermediate → dangerous
            for callee in list(calls.get(ep, set()))[:50]:
                callee_class = callee.split(".")[0] if "." in callee else callee
                if callee_class in dangerous_files:
                    for api_call in dangerous_files[callee_class][:5]:
                        path_info = {
                            "entry_point": ep,
                            "via": callee_class,
                            "dangerous_api": api_call,
                            "path": [ep, callee_class],
                            "depth": 1,
                        }
                        suspicious_paths.append(path_info)

        if suspicious_paths:
            findings.append(
                Finding(
                    id="callgraph:suspicious-paths",
                    type=FindingType.behavior,
                    severity=Severity.high,
                    confidence=0.65,
                    detail=(
                        f"Found {len(suspicious_paths)} call path(s) from entry points "
                        f"to dangerous APIs across {len(entry_points)} entry point(s)."
                    ),
                    provenance=Provenance(extractor=self.name),
                    mappings=Mappings(mitre=["T1204"], owasp_mobile=["M1"]),
                )
            )

        # Serialize the graph to a bounded adjacency list.
        adjacency: dict[str, list[str]] = {
            cls: sorted(callees)[:100]
            for cls, callees in calls.items()
        }

        return AnalyzerResult(
            evidence={
                "entry_points": entry_points[:100],
                "entry_point_count": len(entry_points),
                "classes_with_calls": len(calls),
                "total_call_edges": sum(len(v) for v in calls.values()),
                "suspicious_paths": suspicious_paths[:100],
                "suspicious_path_count": len(suspicious_paths),
                "adjacency_list": dict(list(adjacency.items())[:200]),
            },
            findings=findings,
        )
