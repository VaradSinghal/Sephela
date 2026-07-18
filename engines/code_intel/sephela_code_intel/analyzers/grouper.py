"""Logical grouper — organizes developer classes into functional categories.

Groups classes by their likely role in the application based on package path
heuristics and API usage signals from earlier analyzers. This gives the GenAI
layer (Phase 7) a structured view of the APK's architecture rather than a
flat list of files, enabling more targeted reasoning.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from sephela_code_intel.base import Analyzer, AnalysisContext, AnalyzerResult
from sephela_code_intel.constants import GROUP_INDICATORS


def _classify_to_group(class_name: str, api_categories: list[str]) -> str:
    """Determine the functional group for a class.

    Uses package/class name heuristics first, then falls back to API usage
    signals from the api_usage analyzer.
    """
    name_lower = class_name.lower().replace("/", ".").replace("\\", ".")

    # Check name-based indicators (most reliable).
    for group, indicators in GROUP_INDICATORS.items():
        for indicator in indicators:
            if indicator in name_lower:
                return group

    # Fall back to API usage categories if the name isn't indicative.
    api_to_group: dict[str, str] = {
        "sms_access": "sms",
        "accessibility_abuse": "accessibility",
        "overlay_attack": "ui",
        "reflection": "crypto",
        "dynamic_loading": "native",
        "native_code": "native",
        "crypto_operations": "crypto",
        "process_execution": "native",
        "device_admin": "device_admin",
        "data_exfiltration": "persistence",
        "network_communication": "networking",
        "encoding_obfuscation": "crypto",
    }
    for cat in api_categories:
        if cat in api_to_group:
            return api_to_group[cat]

    return "other"


class GrouperAnalyzer(Analyzer):
    """Group developer classes into functional categories for structured LLM context."""

    name = "grouper"

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        # Get the developer classes from the class filter.
        class_filter_ev = ctx.shared.get("class_filter", {})
        dev_classes: list[str] = []
        if isinstance(class_filter_ev, dict):
            classified = class_filter_ev.get("classified_classes", {})
            if isinstance(classified, dict):
                dev_classes = classified.get("developer", [])
                if not isinstance(dev_classes, list):
                    dev_classes = []

        # Get API usage categories per file to inform grouping.
        api_ev = ctx.shared.get("api_usage", {})
        file_api_categories: dict[str, list[str]] = {}
        if isinstance(api_ev, dict):
            hits_by_cat = api_ev.get("hits_by_category", {})
            if isinstance(hits_by_cat, dict):
                for cat, info in hits_by_cat.items():
                    if isinstance(info, dict):
                        samples = info.get("samples", [])
                        if isinstance(samples, list):
                            for sample in samples:
                                if isinstance(sample, dict):
                                    file_name = sample.get("file", "")
                                    if file_name not in file_api_categories:
                                        file_api_categories[file_name] = []
                                    file_api_categories[file_name].append(cat)

        # Group each developer class.
        groups: dict[str, list[str]] = defaultdict(list)
        for cls in dev_classes:
            # Convert smali name to something matchable
            java_name = cls.lstrip("L").rstrip(";").replace("/", ".")
            # Check if any source file matches this class and has API categories
            api_cats = file_api_categories.get(java_name, [])
            group = _classify_to_group(java_name, api_cats)
            groups[group].append(java_name)

        # Also group source file paths for richer context.
        dev_source_paths: list[str] = []
        if isinstance(class_filter_ev, dict):
            paths = class_filter_ev.get("developer_source_paths", [])
            dev_source_paths = paths if isinstance(paths, list) else []

        source_groups: dict[str, list[str]] = defaultdict(list)
        for path in dev_source_paths:
            api_cats = file_api_categories.get(path, [])
            group = _classify_to_group(path, api_cats)
            source_groups[group].append(path)

        # Build per-group summaries.
        group_summaries: dict[str, Any] = {}
        for group_name in sorted(set(list(groups.keys()) + list(source_groups.keys()))):
            cls_list = groups.get(group_name, [])
            src_list = source_groups.get(group_name, [])
            group_summaries[group_name] = {
                "class_count": len(cls_list),
                "source_file_count": len(src_list),
                "classes": cls_list[:100],
                "source_files": src_list[:100],
            }

        return AnalyzerResult(
            evidence={
                "groups": group_summaries,
                "group_count": len(group_summaries),
                "total_classified": sum(
                    int(s["class_count"]) for s in group_summaries.values()
                ),
                "largest_group": (
                    max(group_summaries, key=lambda g: int(group_summaries[g]["class_count"]))
                    if group_summaries
                    else None
                ),
            }
        )
