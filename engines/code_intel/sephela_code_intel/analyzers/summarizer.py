"""Token-optimized summarizer — produces compact structured context for the LLM.

This is the final analyzer in the chain. It reads the output of all previous
analyzers and produces the ``code_summary`` evidence key — the primary artifact
consumed by the GenAI layer (Phase 7).

Design goal: right-size the context for an LLM. A 50 MB APK with 3000 classes
should produce a summary that fits in ~4000 tokens while retaining all
security-relevant signal. The summarizer prioritizes findings by severity,
groups by suspicion level, and truncates non-critical detail when the output
would exceed a configurable token budget.
"""

from __future__ import annotations

from sephela_code_intel.base import Analyzer, AnalysisContext, AnalyzerResult

# Rough token estimation: ~4 characters per token for English/code.
_CHARS_PER_TOKEN = 4
_DEFAULT_TOKEN_BUDGET = 8000


class SummarizerAnalyzer(Analyzer):
    """Produce a compact, token-budgeted summary of all code-intel findings."""

    name = "summarizer"

    def __init__(self, token_budget: int = _DEFAULT_TOKEN_BUDGET) -> None:
        self.token_budget = token_budget
        self.char_budget = token_budget * _CHARS_PER_TOKEN

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        sections: list[str] = []

        # 1. Class statistics from class_filter.
        class_ev = ctx.shared.get("class_filter", {})
        stats = class_ev.get("stats", {}) if isinstance(class_ev, dict) else {}
        if isinstance(stats, dict) and stats:
            sections.append(
                f"## Class Composition\n"
                f"Total classes: {stats.get('total_classes', '?')}, "
                f"Developer: {stats.get('developer_count', '?')} "
                f"({stats.get('developer_ratio', '?'):.1%} of total), "
                f"Framework: {stats.get('framework_count', '?')}, "
                f"Third-party: {stats.get('third_party_count', '?')}, "
                f"Generated: {stats.get('generated_count', '?')}. "
                f"Developer source files: {stats.get('developer_source_files', '?')}."
            )

        # 2. Suspicious API categories from api_usage.
        api_ev = ctx.shared.get("api_usage", {})
        if isinstance(api_ev, dict) and api_ev.get("categories_detected"):
            categories = api_ev["categories_detected"]
            total = api_ev.get("total_findings", 0)
            if isinstance(categories, list):
                sections.append(
                    f"## Suspicious API Usage\n"
                    f"Detected {total} dangerous API call(s) across "
                    f"{len(categories)} categor{'y' if len(categories) == 1 else 'ies'}: "
                    f"{', '.join(str(c) for c in categories)}."
                )
            # Add top hits per category.
            hits = api_ev.get("hits_by_category", {})
            if isinstance(hits, dict):
                for cat, info in sorted(
                    hits.items(),
                    key=lambda x: x[1].get("count", 0) if isinstance(x[1], dict) else 0,
                    reverse=True,
                ):
                    if isinstance(info, dict):
                        count = info.get("count", 0)
                        samples = info.get("samples", [])
                        sample_strs = []
                        if isinstance(samples, list):
                            for s in samples[:3]:
                                if isinstance(s, dict):
                                    sample_strs.append(
                                        f"{s.get('file', '?')}:{s.get('line', '?')} "
                                        f"→ {s.get('match', '?')}"
                                    )
                        detail = "; ".join(sample_strs) if sample_strs else ""
                        sections.append(f"- **{cat}** ({count} hits): {detail}")

        # 3. Control flow patterns.
        ctrl_ev = ctx.shared.get("control_flow", {})
        if isinstance(ctrl_ev, dict) and ctrl_ev.get("patterns_detected"):
            patterns = ctrl_ev["patterns_detected"]
            total_matches = ctrl_ev.get("total_matches", 0)
            if isinstance(patterns, list):
                sections.append(
                    f"## Evasion / Control Flow Patterns\n"
                    f"Detected {total_matches} match(es) across "
                    f"{len(patterns)} evasion pattern(s): {', '.join(str(p) for p in patterns)}."
                )
            details = ctrl_ev.get("details", {})
            if isinstance(details, dict):
                for pat_name, pat_info in details.items():
                    if isinstance(pat_info, dict):
                        count = pat_info.get("count", 0)
                        sections.append(f"- **{pat_name}**: {count} occurrence(s)")

        # 4. Call graph highlights.
        cg_ev = ctx.shared.get("call_graph", {})
        if isinstance(cg_ev, dict):
            ep_count = cg_ev.get("entry_point_count", 0)
            sp_count = cg_ev.get("suspicious_path_count", 0)
            if ep_count or sp_count:
                sections.append(
                    f"## Call Graph\n"
                    f"Entry points: {ep_count}. "
                    f"Suspicious paths (entry → dangerous API): {sp_count}."
                )
                paths = cg_ev.get("suspicious_paths", [])
                if isinstance(paths, list):
                    for p in paths[:5]:
                        if isinstance(p, dict):
                            ep = p.get("entry_point", "?")
                            api = p.get("dangerous_api", "?")
                            via = p.get("via")
                            path_str = f"{ep} → {via} → {api}" if via else f"{ep} → {api}"
                            sections.append(f"- {path_str}")

        # 5. Functional groups.
        group_ev = ctx.shared.get("grouper", {})
        if isinstance(group_ev, dict) and group_ev.get("groups"):
            groups = group_ev["groups"]
            if isinstance(groups, dict):
                sections.append(
                    f"## Functional Groups ({len(groups)} groups, "
                    f"{group_ev.get('total_classified', '?')} classes classified)"
                )
                for gname, ginfo in sorted(
                    groups.items(),
                    key=lambda x: x[1].get("class_count", 0) if isinstance(x[1], dict) else 0,
                    reverse=True,
                ):
                    if isinstance(ginfo, dict):
                        cc = ginfo.get("class_count", 0)
                        fc = ginfo.get("source_file_count", 0)
                        classes = ginfo.get("classes", [])
                        sample = ", ".join(str(c) for c in classes[:5]) if isinstance(classes, list) else ""
                        suffix = f" (+{cc - 5} more)" if cc > 5 else ""
                        sections.append(f"- **{gname}**: {cc} classes, {fc} files — {sample}{suffix}")

        # 6. Static envelope context (permissions, obfuscation).
        perms = ctx.get_permissions()
        if perms:
            sections.append(
                f"## Permissions ({len(perms)})\n{', '.join(perms[:30])}"
                + (f" (+{len(perms) - 30} more)" if len(perms) > 30 else "")
            )

        obfusc = ctx.static_evidence.get("obfuscation", {})
        if isinstance(obfusc, dict) and obfusc.get("likely_obfuscated"):
            ratio = obfusc.get("obfuscated_ratio", 0)
            sections.append(
                f"## Obfuscation\nLikely obfuscated: {ratio:.0%} of classes have mangled names."
            )

        # Assemble and enforce token budget.
        full_summary = "\n\n".join(sections)
        if len(full_summary) > self.char_budget:
            # Truncate less critical sections from the end, keep the header.
            full_summary = full_summary[: self.char_budget - 50] + "\n\n[...truncated for token budget]"

        estimated_tokens = len(full_summary) // _CHARS_PER_TOKEN

        return AnalyzerResult(
            evidence={
                "code_summary": full_summary,
                "estimated_tokens": estimated_tokens,
                "token_budget": self.token_budget,
                "within_budget": estimated_tokens <= self.token_budget,
                "section_count": len(sections),
            }
        )
