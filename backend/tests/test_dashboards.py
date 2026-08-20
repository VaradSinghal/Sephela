"""Structural validation of the Grafana dashboards and Prometheus rules.

There is no Grafana in CI, so these do not prove a dashboard *renders*. They check the
class of mistake that a running Grafana would never report at all: a panel querying a
metric nothing emits shows an empty graph, and an empty graph on a health dashboard reads
as "no problems here". Same for an alert that can never fire.

That is the one check worth having here, and it is only possible because
``pipeline_metrics.metric_names()`` enumerates what the application can produce. Everything
else in this file is cheap structural hygiene layered on top.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from app.core.pipeline_metrics import metric_names

yaml = pytest.importorskip("yaml")

_ROOT = Path(__file__).resolve().parents[2] / "infra" / "grafana"
_DASHBOARDS = _ROOT / "dashboards"
_RULES = _ROOT / "rules"

#: Metrics produced by ``app.core.metrics`` rather than the pipeline module. Enumerated
#: here because that module builds them inside ``setup_metrics`` and so cannot list them
#: without a FastAPI app.
_HTTP_METRICS = frozenset(
    {
        "http_requests_total",
        "http_request_duration_seconds",
        "http_request_errors_total",
    }
)

#: Recording rules defined in the rule files. A dashboard may query these even though no
#: application code emits them, because Prometheus itself creates them.
_RECORDED = frozenset(
    {
        "sephela:job_failure_ratio:5m",
        "sephela:stage_failure_ratio:5m",
        "sephela:llm_failure_ratio:10m",
        "sephela:tokens_per_sample:6h",
    }
)

#: PromQL functions, keywords, and aggregation modifiers that look like metric names to a
#: regex. Without this list every ``rate(`` and ``by (`` would be reported as a missing
#: metric.
_PROMQL_TOKENS = frozenset(
    {
        "rate",
        "irate",
        "increase",
        "deriv",
        "delta",
        "idelta",
        "sum",
        "avg",
        "min",
        "max",
        "count",
        "count_values",
        "stddev",
        "stdvar",
        "topk",
        "bottomk",
        "quantile",
        "histogram_quantile",
        "clamp_min",
        "clamp_max",
        "clamp",
        "round",
        "abs",
        "ceil",
        "floor",
        "ln",
        "log2",
        "log10",
        "exp",
        "sqrt",
        "absent",
        "absent_over_time",
        "changes",
        "resets",
        "label_replace",
        "label_join",
        "vector",
        "scalar",
        "time",
        "timestamp",
        "predict_linear",
        "holt_winters",
        "avg_over_time",
        "sum_over_time",
        "min_over_time",
        "max_over_time",
        "count_over_time",
        "quantile_over_time",
        "stddev_over_time",
        "last_over_time",
        "present_over_time",
        "by",
        "without",
        "on",
        "ignoring",
        "group_left",
        "group_right",
        "offset",
        "and",
        "or",
        "unless",
        "bool",
        "le",
        "humanize",
        "humanizePercentage",
        "label_values",
        "status",
        "stage",
        "severity",
        "tier",
        "queue",
        "model",
        "agent",
        "outcome",
        "path",
        "method",
    }
)

#: An identifier in PromQL. Whether it is a metric or a function is decided by what
#: follows it, checked separately: a lookahead here would let the regex backtrack and
#: shorten the match until the lookahead passed, turning `rate(` into `rat`.
_IDENT_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_:]*")

#: Quoted strings, blanked before parsing. A label value like `path="/health/ready"`
#: otherwise contributes both a stray identifier and a stray `/`.
_QUOTED_RE = re.compile(r"\"[^\"]*\"|'[^']*'")

#: Suffixes Prometheus derives from a histogram, which panels query directly.
_HISTOGRAM_SUFFIXES = ("_bucket", "_count", "_sum")


def _base_name(name: str) -> str:
    for suffix in _HISTOGRAM_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _strip_strings(expr: str) -> str:
    """Blank out quoted strings so label values are not parsed as expression syntax."""
    return _QUOTED_RE.sub('""', expr)


def _referenced_metrics(expr: str) -> set[str]:
    """Every metric name a PromQL expression queries.

    Three things that look like identifiers and are not metrics: one followed by `(` is a
    function call, one preceded by `.` is part of a longer path, and one preceded by a
    digit is a duration unit — the `m` in `[5m]` and the `h` in `offset 24h`.
    """
    text = _strip_strings(expr)
    found = set()
    for match in _IDENT_RE.finditer(text):
        token = match.group(0)
        if token in _PROMQL_TOKENS:
            continue
        if match.start() > 0 and (
            text[match.start() - 1] == "." or text[match.start() - 1].isdigit()
        ):
            continue
        if text[match.end() :].lstrip().startswith("("):
            continue
        found.add(_base_name(token))
    return found


def _panels(dashboard: dict[str, Any]) -> list[dict[str, Any]]:
    """Every panel, including any nested inside a collapsed row."""
    out: list[dict[str, Any]] = []
    for panel in dashboard.get("panels", []):
        out.append(panel)
        out.extend(panel.get("panels", []))
    return out


def _queryable(panel: dict[str, Any]) -> bool:
    return panel.get("type") != "row"


@pytest.fixture(scope="module")
def dashboards() -> dict[str, dict[str, Any]]:
    files = sorted(_DASHBOARDS.glob("*.json"))
    assert files, f"no dashboards found under {_DASHBOARDS}"
    return {path.name: json.loads(path.read_text()) for path in files}


@pytest.fixture(scope="module")
def rule_files() -> dict[str, dict[str, Any]]:
    files = sorted(_RULES.glob("*.yaml")) + sorted(_RULES.glob("*.yml"))
    assert files, f"no rule files found under {_RULES}"
    return {path.name: yaml.safe_load(path.read_text()) for path in files}


def _known_metrics() -> frozenset[str]:
    return frozenset(metric_names() | _HTTP_METRICS | _RECORDED)


# ---------------------------------------------------------------------------
# The check this file exists for
# ---------------------------------------------------------------------------


class TestPanelsQueryRealMetrics:
    def test_every_panel_query_references_a_metric_the_app_emits(
        self, dashboards: dict[str, dict[str, Any]]
    ) -> None:
        # A renamed metric leaves a permanently empty panel, and an empty panel on a
        # health dashboard is worse than a missing one: it reads as "nothing wrong".
        known = _known_metrics()
        unknown: list[str] = []

        for name, dashboard in dashboards.items():
            for panel in _panels(dashboard):
                for target in panel.get("targets", []):
                    expr = target.get("expr", "")
                    for metric in _referenced_metrics(expr) - known:
                        unknown.append(f"{name}:{panel.get('title')!r} -> {metric}")

        assert not unknown, "panels query metrics nothing emits:\n" + "\n".join(unknown)

    def test_every_template_variable_query_references_a_real_metric(
        self, dashboards: dict[str, dict[str, Any]]
    ) -> None:
        # A variable resolving to nothing leaves every panel that filters on it empty,
        # which looks like the platform is idle.
        known = _known_metrics()
        unknown: list[str] = []

        for name, dashboard in dashboards.items():
            for variable in dashboard.get("templating", {}).get("list", []):
                query = variable.get("query")
                if not isinstance(query, str) or variable.get("type") == "datasource":
                    continue
                for metric in _referenced_metrics(query) - known:
                    unknown.append(f"{name}:{variable.get('name')} -> {metric}")

        assert not unknown, "\n".join(unknown)

    def test_every_alert_and_recording_rule_references_a_real_metric(
        self, rule_files: dict[str, dict[str, Any]]
    ) -> None:
        # An alert on a metric nothing emits never fires, which is indistinguishable from
        # the condition never occurring.
        known = _known_metrics()
        unknown: list[str] = []

        for name, document in rule_files.items():
            for group in document.get("groups", []):
                for rule in group.get("rules", []):
                    label = rule.get("alert") or rule.get("record")
                    for metric in _referenced_metrics(rule["expr"]) - known:
                        unknown.append(f"{name}:{label} -> {metric}")

        assert not unknown, "rules query metrics nothing emits:\n" + "\n".join(unknown)

    def test_every_recording_rule_the_dashboards_use_is_actually_defined(
        self, rule_files: dict[str, dict[str, Any]]
    ) -> None:
        # `_RECORDED` is an allowlist, so it could otherwise let a dashboard reference a
        # rule that was deleted.
        defined = {
            rule["record"]
            for document in rule_files.values()
            for group in document.get("groups", [])
            for rule in group.get("rules", [])
            if "record" in rule
        }

        assert defined >= _RECORDED, _RECORDED - defined


# ---------------------------------------------------------------------------
# Dashboard hygiene
# ---------------------------------------------------------------------------


class TestDashboardStructure:
    def test_every_dashboard_parses_and_has_the_fields_grafana_needs(
        self, dashboards: dict[str, dict[str, Any]]
    ) -> None:
        for name, dashboard in dashboards.items():
            assert dashboard.get("uid"), f"{name}: no uid, so it cannot be linked to"
            assert dashboard.get("title"), f"{name}: no title"
            assert dashboard.get("panels"), f"{name}: no panels"

    def test_dashboard_uids_are_unique(self, dashboards: dict[str, dict[str, Any]]) -> None:
        # Provisioning keys on the uid, so a collision silently replaces one dashboard
        # with another.
        uids = [d["uid"] for d in dashboards.values()]

        assert len(uids) == len(set(uids)), uids

    def test_panel_ids_are_unique_within_a_dashboard(
        self, dashboards: dict[str, dict[str, Any]]
    ) -> None:
        for name, dashboard in dashboards.items():
            ids = [p["id"] for p in _panels(dashboard) if "id" in p]
            assert len(ids) == len(set(ids)), f"{name}: duplicate panel ids {ids}"

    def test_every_queryable_panel_has_at_least_one_target(
        self, dashboards: dict[str, dict[str, Any]]
    ) -> None:
        # A panel with no target renders blank forever.
        for name, dashboard in dashboards.items():
            for panel in _panels(dashboard):
                if _queryable(panel):
                    assert panel.get("targets"), f"{name}: {panel.get('title')!r} has no target"

    def test_every_target_has_a_non_empty_expression(
        self, dashboards: dict[str, dict[str, Any]]
    ) -> None:
        for name, dashboard in dashboards.items():
            for panel in _panels(dashboard):
                for target in panel.get("targets", []):
                    assert target.get("expr", "").strip(), f"{name}: {panel.get('title')!r}"

    def test_every_target_has_a_ref_id(self, dashboards: dict[str, dict[str, Any]]) -> None:
        # Grafana needs it to distinguish two series in one panel.
        for name, dashboard in dashboards.items():
            for panel in _panels(dashboard):
                ref_ids = [t.get("refId") for t in panel.get("targets", [])]
                assert all(ref_ids), f"{name}: {panel.get('title')!r} has an unnamed target"
                assert len(ref_ids) == len(set(ref_ids)), f"{name}: duplicate refId"

    def test_every_queryable_panel_names_its_datasource(
        self, dashboards: dict[str, dict[str, Any]]
    ) -> None:
        # Left implicit, a panel binds to whatever the default datasource happens to be
        # on the Grafana it is imported into.
        for name, dashboard in dashboards.items():
            for panel in _panels(dashboard):
                if _queryable(panel):
                    assert panel.get("datasource"), f"{name}: {panel.get('title')!r}"

    def test_the_datasource_variable_exists_wherever_panels_reference_it(
        self, dashboards: dict[str, dict[str, Any]]
    ) -> None:
        for name, dashboard in dashboards.items():
            uses_variable = any(
                "${datasource}" in json.dumps(panel) for panel in _panels(dashboard)
            )
            if not uses_variable:
                continue
            declared = {v.get("name") for v in dashboard.get("templating", {}).get("list", [])}
            assert "datasource" in declared, f"{name}: panels use $datasource but it is undeclared"

    def test_every_dashboard_is_in_utc(self, dashboards: dict[str, dict[str, Any]]) -> None:
        # Evidence timestamps and job records are all UTC; a dashboard in browser time
        # makes correlating them with a log line an exercise in arithmetic.
        for name, dashboard in dashboards.items():
            assert dashboard.get("timezone") == "utc", name

    def test_every_dashboard_explains_what_it_is_for(
        self, dashboards: dict[str, dict[str, Any]]
    ) -> None:
        for name, dashboard in dashboards.items():
            assert len(dashboard.get("description", "")) > 40, f"{name}: no useful description"

    def test_a_variable_that_filters_panels_is_referenced_by_at_least_one(
        self, dashboards: dict[str, dict[str, Any]]
    ) -> None:
        # An unused filter is a control that appears to do something and does not.
        for name, dashboard in dashboards.items():
            body = json.dumps(dashboard.get("panels", []))
            for variable in dashboard.get("templating", {}).get("list", []):
                if variable.get("type") == "datasource":
                    continue
                token = f"${variable['name']}"
                assert token in body, f"{name}: variable {variable['name']} filters nothing"


class TestExpectedDashboards:
    def test_the_three_operational_views_are_present(
        self, dashboards: dict[str, dict[str, Any]]
    ) -> None:
        # Health, quality, and cost answer different questions, and merging any two of
        # them produces a dashboard nobody reads during an incident.
        uids = {d["uid"] for d in dashboards.values()}

        assert uids >= {
            "sephela-pipeline-health",
            "sephela-analysis-quality",
            "sephela-llm-cost",
        }

    def test_the_quality_dashboard_surfaces_degradation(
        self, dashboards: dict[str, dict[str, Any]]
    ) -> None:
        # The point of that dashboard: a pipeline running three of seven stages produces
        # confident-looking scores from a fraction of the evidence, and only the skip and
        # partial panels say so.
        quality = next(d for d in dashboards.values() if d["uid"] == "sephela-analysis-quality")
        body = json.dumps(quality)

        assert 'status=\\"skipped\\"' in body
        assert 'status=\\"partial\\"' in body

    def test_the_cost_dashboard_reports_spend_per_sample(
        self, dashboards: dict[str, dict[str, Any]]
    ) -> None:
        # Total tokens grows with volume; per-sample is the number that shows a
        # regression, and it is the one a budget conversation needs.
        cost = next(d for d in dashboards.values() if d["uid"] == "sephela-llm-cost")
        titles = [p.get("title", "") for p in _panels(cost)]

        assert any("per analysed sample" in t for t in titles), titles


# ---------------------------------------------------------------------------
# Rule hygiene
# ---------------------------------------------------------------------------


class TestRuleStructure:
    def test_every_rule_file_parses_into_groups(
        self, rule_files: dict[str, dict[str, Any]]
    ) -> None:
        for name, document in rule_files.items():
            assert document.get("groups"), f"{name}: no groups"

    def test_group_names_are_unique(self, rule_files: dict[str, dict[str, Any]]) -> None:
        names = [g["name"] for d in rule_files.values() for g in d["groups"]]

        assert len(names) == len(set(names)), names

    def test_alert_names_are_unique(self, rule_files: dict[str, dict[str, Any]]) -> None:
        names = [
            rule["alert"]
            for d in rule_files.values()
            for g in d["groups"]
            for rule in g["rules"]
            if "alert" in rule
        ]

        assert len(names) == len(set(names)), names

    def test_every_alert_has_a_severity_and_a_component(
        self, rule_files: dict[str, dict[str, Any]]
    ) -> None:
        # Routing keys on severity; an unlabelled alert goes nowhere.
        for name, document in rule_files.items():
            for group in document["groups"]:
                for rule in group["rules"]:
                    if "alert" not in rule:
                        continue
                    labels = rule.get("labels", {})
                    assert labels.get("severity") in {"info", "warning", "critical"}, (
                        f"{name}:{rule['alert']}"
                    )
                    assert labels.get("component"), f"{name}:{rule['alert']}"

    def test_every_alert_says_what_to_do_about_it(
        self, rule_files: dict[str, dict[str, Any]]
    ) -> None:
        # An alert whose body only restates its own expression cannot be acted on at 3am.
        for name, document in rule_files.items():
            for group in document["groups"]:
                for rule in group["rules"]:
                    if "alert" not in rule:
                        continue
                    annotations = rule.get("annotations", {})
                    assert annotations.get("summary"), f"{name}:{rule['alert']}"
                    assert len(annotations.get("description", "")) > 60, (
                        f"{name}:{rule['alert']} has no useful description"
                    )

    def test_every_alert_waits_before_firing(self, rule_files: dict[str, dict[str, Any]]) -> None:
        # Without `for`, a single scrape trips the alert. On a low-volume platform one
        # failed job is enough to make a ratio look catastrophic.
        for name, document in rule_files.items():
            for group in document["groups"]:
                for rule in group["rules"]:
                    if "alert" in rule:
                        assert rule.get("for"), f"{name}:{rule['alert']} fires on a single scrape"

    def test_every_ratio_alert_guards_its_denominator(
        self, rule_files: dict[str, dict[str, Any]]
    ) -> None:
        # This is the difference between an alert that works and one that gets muted: on
        # an idle system an unguarded ratio is 0/0, and any near-zero denominator produces
        # a spurious 100%.
        for name, document in rule_files.items():
            for group in document["groups"]:
                for rule in group["rules"]:
                    label = rule.get("alert") or rule.get("record")
                    # Strings first: `path="/health/ready"` is a label value rather than a
                    # division, and flagging it would train the reader to ignore this.
                    expr = _strip_strings(rule["expr"])
                    if "/" not in expr:
                        continue
                    # Either guarded here, or delegated to a recording rule that is.
                    guarded = "clamp_min" in expr or "sephela:" in expr
                    assert guarded, f"{name}:{label} divides without guarding the denominator"

    def test_no_alert_fires_on_a_stage_being_skipped(
        self, rule_files: dict[str, dict[str, Any]]
    ) -> None:
        # Skipping is a configuration choice — dynamic analysis and the AI stage are off
        # by default — so an alert on it would fire permanently on a stock install and
        # train everyone to ignore the channel.
        for name, document in rule_files.items():
            for group in document["groups"]:
                for rule in group["rules"]:
                    if "alert" in rule:
                        assert 'status="skipped"' not in rule["expr"], f"{name}:{rule['alert']}"

    def test_no_alert_fires_on_partial_jobs(self, rule_files: dict[str, dict[str, Any]]) -> None:
        # Same reasoning: `partial` is the expected outcome of running a subset of the
        # pipeline, which is what the README describes as the default deployment.
        for name, document in rule_files.items():
            for group in document["groups"]:
                for rule in group["rules"]:
                    if "alert" in rule:
                        assert 'status="partial"' not in rule["expr"], f"{name}:{rule['alert']}"

    def test_every_group_declares_an_evaluation_interval(
        self, rule_files: dict[str, dict[str, Any]]
    ) -> None:
        for name, document in rule_files.items():
            for group in document["groups"]:
                assert group.get("interval"), f"{name}:{group['name']}"

    def test_recording_rule_names_follow_the_prometheus_convention(
        self, rule_files: dict[str, dict[str, Any]]
    ) -> None:
        # level:metric:operation, so a recorded series is never mistaken for one the
        # application emits.
        for name, document in rule_files.items():
            for group in document["groups"]:
                for rule in group["rules"]:
                    if "record" in rule:
                        assert rule["record"].count(":") == 2, f"{name}:{rule['record']}"


class TestReferencedRunbooks:
    def test_every_runbook_annotation_points_at_a_file_that_exists(
        self, rule_files: dict[str, dict[str, Any]]
    ) -> None:
        # A dead runbook link is discovered at exactly the wrong moment.
        repo_root = Path(__file__).resolve().parents[2]

        for name, document in rule_files.items():
            for group in document["groups"]:
                for rule in group["rules"]:
                    runbook = rule.get("annotations", {}).get("runbook")
                    if not runbook:
                        continue
                    assert (repo_root / runbook).exists(), f"{name}:{rule['alert']} -> {runbook}"
