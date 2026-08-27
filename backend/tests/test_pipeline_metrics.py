"""Domain metrics for the pipeline.

Two properties are worth more than the individual counters. First, instrumentation must
never be able to fail a stage: the stage produces the analysis and the metric only
describes it, so a broken collector has to degrade to no metrics rather than to no
result. Second, every label must come from a closed set — a job id or a package name as
a label grows the series count without bound, which takes Prometheus down rather than
the app.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.core import pipeline_metrics as pm

prometheus_client = pytest.importorskip("prometheus_client")


@pytest.fixture
def metrics(monkeypatch: pytest.MonkeyPatch):
    """Register the collectors into a private registry, isolated per test.

    Without a fresh registry, two tests registering the same metric name raise a
    duplicate-collector error, and counters carry over between them.
    """
    registry = prometheus_client.CollectorRegistry()
    original_counter = prometheus_client.Counter
    original_gauge = prometheus_client.Gauge
    original_histogram = prometheus_client.Histogram

    def scoped(factory: Any):
        def _build(*args: Any, **kwargs: Any) -> Any:
            kwargs.setdefault("registry", registry)
            return factory(*args, **kwargs)

        return _build

    monkeypatch.setattr(prometheus_client, "Counter", scoped(original_counter))
    monkeypatch.setattr(prometheus_client, "Gauge", scoped(original_gauge))
    monkeypatch.setattr(prometheus_client, "Histogram", scoped(original_histogram))
    monkeypatch.setattr(pm.settings, "metrics_enabled", True)
    monkeypatch.setattr(pm, "_METRICS", {})
    monkeypatch.setattr(pm, "_REGISTERED", False)

    pm._register()
    return registry


def value_of(registry: Any, name: str, **labels: str) -> float | None:
    """The current value of one sample, or None if the series does not exist."""
    return registry.get_sample_value(name, labels or None)


# ---------------------------------------------------------------------------
# Disabled by default
# ---------------------------------------------------------------------------


class TestDisabled:
    def test_recording_is_a_no_op_when_metrics_are_off(self, monkeypatch) -> None:
        # Off is the default, so this is the path almost every deployment takes.
        monkeypatch.setattr(pm.settings, "metrics_enabled", False)
        monkeypatch.setattr(pm, "_METRICS", {})
        monkeypatch.setattr(pm, "_REGISTERED", False)

        pm.record_job("completed", duration_seconds=1.0)
        pm.record_stage("static", "ok", duration_seconds=1.0, attempt=2)
        pm.record_findings("static", {"critical": 1})
        pm.record_risk(80.0, "malicious")
        pm.set_queue_depth("static", 5)
        pm.record_llm_call(model="m", agent="a", outcome="completed", tokens=10)

        assert pm._METRICS == {}

    def test_the_worker_exporter_does_nothing_when_metrics_are_off(self, monkeypatch) -> None:
        monkeypatch.setattr(pm.settings, "metrics_enabled", False)
        monkeypatch.setattr(pm, "_METRICS", {})
        monkeypatch.setattr(pm, "_REGISTERED", False)
        started: list[int] = []
        monkeypatch.setattr(
            prometheus_client, "start_http_server", lambda port: started.append(port)
        )

        pm.setup_worker_metrics()

        assert started == []


class TestRegistrationIsIdempotent:
    def test_registering_twice_does_not_raise(self, metrics) -> None:
        # Both the worker signal and the first recording call reach _register.
        pm._register()
        pm._register()

        assert pm._METRICS


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


class TestJobMetrics:
    def test_a_completed_job_is_counted_by_status(self, metrics) -> None:
        pm.record_job("completed")

        assert value_of(metrics, "sephela_jobs_total", status="completed") == 1

    @pytest.mark.parametrize("status", ["completed", "partial", "failed", "cancelled"])
    def test_every_terminal_status_gets_its_own_series(self, metrics, status: str) -> None:
        # `partial` is the one that matters most: a deployment running a subset of stages
        # produces it constantly, and it must not be lumped in with `completed`.
        pm.record_job(status)

        assert value_of(metrics, "sephela_jobs_total", status=status) == 1

    def test_the_duration_is_observed_when_supplied(self, metrics) -> None:
        pm.record_job("completed", duration_seconds=42.0)

        assert value_of(metrics, "sephela_job_duration_seconds_count") == 1
        assert value_of(metrics, "sephela_job_duration_seconds_sum") == 42.0

    def test_a_job_with_no_measurable_duration_is_still_counted(self, metrics) -> None:
        # A job cancelled before it started has no span, and losing the count with it
        # would understate the cancellation rate.
        pm.record_job("cancelled", duration_seconds=None)

        assert value_of(metrics, "sephela_jobs_total", status="cancelled") == 1
        assert value_of(metrics, "sephela_job_duration_seconds_count") == 0


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------


class TestStageMetrics:
    def test_a_stage_outcome_is_counted_by_engine_and_status(self, metrics) -> None:
        pm.record_stage("static", "ok")

        assert value_of(metrics, "sephela_stage_total", stage="static", status="ok") == 1

    def test_a_skip_is_recorded_rather_than_omitted(self, metrics) -> None:
        # How often a deployment runs partial is one of the more useful things to know
        # about it, and an absent series cannot answer that.
        pm.record_stage("dynamic", "skipped")

        assert value_of(metrics, "sephela_stage_total", stage="dynamic", status="skipped") == 1

    def test_the_duration_is_labelled_by_stage(self, metrics) -> None:
        pm.record_stage("static", "ok", duration_seconds=12.5)

        assert value_of(metrics, "sephela_stage_duration_seconds_sum", stage="static") == 12.5

    def test_a_retry_is_counted_separately(self, metrics) -> None:
        # A stage that only succeeded on its third attempt is worth a second look, and
        # the success count alone hides that entirely.
        pm.record_stage("static", "ok", attempt=3)

        assert value_of(metrics, "sephela_stage_retries_total", stage="static") == 1

    def test_a_first_attempt_is_not_counted_as_a_retry(self, metrics) -> None:
        pm.record_stage("static", "ok", attempt=1)

        assert value_of(metrics, "sephela_stage_retries_total", stage="static") is None

    def test_the_duration_buckets_bracket_the_celery_time_limits(self) -> None:
        # 300s and 600s are where a stage stops being slow and starts being killed, so
        # the histogram has to be able to distinguish those.
        assert 300 in pm._STAGE_DURATION_BUCKETS
        assert 600 in pm._STAGE_DURATION_BUCKETS


# ---------------------------------------------------------------------------
# Findings and risk
# ---------------------------------------------------------------------------


class TestFindingMetrics:
    def test_findings_are_counted_per_severity(self, metrics) -> None:
        pm.record_findings("static", {"critical": 2, "high": 5})

        assert value_of(metrics, "sephela_findings_total", stage="static", severity="critical") == 2
        assert value_of(metrics, "sephela_findings_total", stage="static", severity="high") == 5

    def test_a_zero_count_creates_no_series(self, metrics) -> None:
        # Otherwise every stage would emit five severity series on every job, most of
        # them permanently zero.
        pm.record_findings("static", {"critical": 0})

        assert (
            value_of(metrics, "sephela_findings_total", stage="static", severity="critical") is None
        )

    def test_an_empty_mapping_is_accepted(self, metrics) -> None:
        pm.record_findings("scoring", {})


class TestRiskMetrics:
    def test_the_score_and_tier_are_both_recorded(self, metrics) -> None:
        pm.record_risk(82.5, "malicious")

        assert value_of(metrics, "sephela_risk_score_sum") == 82.5
        assert value_of(metrics, "sephela_risk_tier_total", tier="malicious") == 1

    def test_the_score_is_clamped_into_range(self, metrics) -> None:
        # The histogram's top bucket is 100; a score above it would land in +Inf and make
        # the distribution unreadable.
        pm.record_risk(140.0, "critical")

        assert value_of(metrics, "sephela_risk_score_sum") == 100.0

    def test_a_negative_score_is_clamped_too(self, metrics) -> None:
        pm.record_risk(-5.0, "benign")

        assert value_of(metrics, "sephela_risk_score_sum") == 0.0

    def test_the_buckets_follow_the_tier_boundaries(self) -> None:
        # A dashboard reads the distribution against the tiers, so evenly-spaced buckets
        # that straddle a boundary would misreport how many samples are malicious.
        assert 40 in pm._RISK_SCORE_BUCKETS
        assert 100 in pm._RISK_SCORE_BUCKETS


# ---------------------------------------------------------------------------
# Queues
# ---------------------------------------------------------------------------


class TestQueueDepth:
    def test_the_depth_is_a_gauge_that_can_go_down(self, metrics) -> None:
        # It is sampled, not accumulated: a counter would report the total work ever
        # queued, which says nothing about whether the workers are behind now.
        pm.set_queue_depth("static", 12)
        pm.set_queue_depth("static", 3)

        assert value_of(metrics, "sephela_queue_depth", queue="static") == 3

    def test_each_queue_has_its_own_series(self, metrics) -> None:
        pm.set_queue_depth("static", 1)
        pm.set_queue_depth("ai", 9)

        assert value_of(metrics, "sephela_queue_depth", queue="static") == 1
        assert value_of(metrics, "sephela_queue_depth", queue="ai") == 9


# ---------------------------------------------------------------------------
# LLM cost
# ---------------------------------------------------------------------------


class TestLLMMetrics:
    def test_a_call_is_counted_by_model_agent_and_outcome(self, metrics) -> None:
        pm.record_llm_call(
            model="anthropic/nvidia/nemotron-3-super-120b-a12b:free", agent="manifest_agent", outcome="completed"
        )

        assert (
            value_of(
                metrics,
                "sephela_llm_calls_total",
                model="anthropic/nvidia/nemotron-3-super-120b-a12b:free",
                agent="manifest_agent",
                outcome="completed",
            )
            == 1
        )

    def test_tokens_are_attributed_to_the_model_and_agent(self, metrics) -> None:
        # This is what turns cost per analysis from an invoice line into a metric, and
        # per-agent is the granularity that says which prompt to shorten.
        pm.record_llm_call(
            model="anthropic/nvidia/nemotron-3-super-120b-a12b:free", agent="code_agent", outcome="completed", tokens=4096
        )

        assert (
            value_of(
                metrics,
                "sephela_llm_tokens_total",
                model="anthropic/nvidia/nemotron-3-super-120b-a12b:free",
                agent="code_agent",
            )
            == 4096
        )

    def test_a_failed_call_is_counted_without_tokens(self, metrics) -> None:
        pm.record_llm_call(model="m", agent="a", outcome="failed", tokens=0)

        assert (
            value_of(metrics, "sephela_llm_calls_total", model="m", agent="a", outcome="failed")
            == 1
        )
        assert value_of(metrics, "sephela_llm_tokens_total", model="m", agent="a") is None

    def test_latency_is_observed(self, metrics) -> None:
        pm.record_llm_call(model="m", agent="a", outcome="completed", duration_seconds=8.5)

        assert (
            value_of(metrics, "sephela_llm_call_duration_seconds_sum", model="m", agent="a") == 8.5
        )

    def test_a_partial_outcome_gets_its_own_series(self, metrics) -> None:
        # `partial` means the validator flagged the output but it was kept — worth
        # distinguishing from a clean completion when watching quality.
        pm.record_llm_call(model="m", agent="a", outcome="partial")

        assert (
            value_of(metrics, "sephela_llm_calls_total", model="m", agent="a", outcome="partial")
            == 1
        )


# ---------------------------------------------------------------------------
# Contract with the dashboards
# ---------------------------------------------------------------------------


def exposed_names(registry: Any) -> set[str]:
    """Metric names as they appear on /metrics.

    Read from the registry's exposition rather than from ``describe()``: a Counter
    created as ``sephela_jobs_total`` describes itself as ``sephela_jobs`` and only
    *exposes* the ``_total`` suffix, and the exposed name is what a dashboard queries.
    """
    names: set[str] = set()
    for family in registry.collect():
        for sample in family.samples:
            name = sample.name
            # `_created` is prometheus_client's OpenMetrics extra — a gauge of when the
            # counter was first observed. Skipped rather than stripped, because
            # stripping turns `sephela_jobs_created` into `sephela_jobs`, which is not a
            # name anything queries.
            if name.endswith("_created"):
                continue
            for suffix in ("_bucket", "_count", "_sum"):
                if name.endswith(suffix):
                    name = name[: -len(suffix)]
                    break
            names.add(name)
    return names


def record_one_of_everything() -> None:
    """Drive every recording helper once.

    A labelled collector exposes no series until something calls ``.labels()``, so the
    exposition is only complete after each recorder has run. Which makes this the
    stronger assertion anyway: it proves each helper creates the series it claims to,
    rather than that a collector object was constructed.
    """
    pm.record_job("completed", duration_seconds=1.0)
    pm.record_stage("static", "ok", duration_seconds=1.0, attempt=2)
    pm.record_findings("static", {"critical": 1})
    pm.record_risk(50.0, "suspicious")
    pm.set_queue_depth("static", 1)
    pm.record_llm_call(model="m", agent="a", outcome="completed", tokens=1, duration_seconds=1.0)


class TestMetricNames:
    def test_every_declared_name_is_actually_exposed(self, metrics) -> None:
        # `metric_names()` is what test_dashboards.py checks panels against, so a name
        # listed there but never created would let a broken panel pass.
        record_one_of_everything()

        exposed = exposed_names(metrics)

        assert pm.metric_names() <= exposed, pm.metric_names() - exposed

    def test_nothing_is_exposed_that_is_not_declared(self, metrics) -> None:
        # The other direction: a metric added here but not listed in metric_names()
        # cannot be checked against a dashboard, so it would drift unnoticed.
        record_one_of_everything()

        exposed = exposed_names(metrics)

        assert exposed <= pm.metric_names(), exposed - pm.metric_names()

    def test_every_name_is_namespaced(self) -> None:
        # Sharing a metric name with something else on the same Prometheus merges two
        # unrelated series.
        for name in pm.metric_names():
            assert name.startswith("sephela_"), name

    def test_the_names_do_not_collide_with_the_http_metrics(self) -> None:
        from app.core import metrics as http_metrics

        assert http_metrics is not None
        assert not any(name.startswith("http_") for name in pm.metric_names())


class TestLabelCardinality:
    def test_no_metric_is_labelled_by_job_or_sample(self, metrics) -> None:
        # A job id or a sample hash as a label is unbounded: one series per analysis
        # forever, which takes Prometheus down rather than the app.
        forbidden = {"job", "job_id", "sample", "sha256", "package", "package_name", "id"}

        for metric in pm._METRICS.values():
            labels = set(getattr(metric, "_labelnames", ()))
            assert not (labels & forbidden), (metric.describe()[0].name, labels)

    def test_the_label_sets_are_the_ones_the_dashboards_group_by(self, metrics) -> None:
        labels = {
            key: set(getattr(metric, "_labelnames", ())) for key, metric in pm._METRICS.items()
        }

        assert labels["stage_total"] == {"stage", "status"}
        assert labels["findings_total"] == {"stage", "severity"}
        assert labels["llm_tokens_total"] == {"model", "agent"}
        assert labels["queue_depth"] == {"queue"}


# ---------------------------------------------------------------------------
# Instrumentation must never break a stage
# ---------------------------------------------------------------------------


class TestFailureIsolation:
    def test_a_missing_prometheus_client_degrades_to_no_metrics(self, monkeypatch) -> None:
        # The dependency is declared, but the module is imported by engines and workers
        # whose images can be built without it.
        import builtins

        real_import = builtins.__import__

        def _fail(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "prometheus_client":
                raise ImportError("no prometheus_client")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(pm.settings, "metrics_enabled", True)
        monkeypatch.setattr(pm, "_METRICS", {})
        monkeypatch.setattr(pm, "_REGISTERED", False)
        monkeypatch.setattr(builtins, "__import__", _fail)

        pm._register()

        assert pm._METRICS == {}

    def test_a_worker_that_cannot_bind_the_port_still_starts(self, metrics, monkeypatch) -> None:
        # Losing metrics is a monitoring gap; refusing to start is an outage.
        def _boom(port: int) -> None:
            raise OSError("address already in use")

        monkeypatch.setattr(prometheus_client, "start_http_server", _boom)

        pm.setup_worker_metrics()

    def test_the_worker_exporter_uses_the_configured_port(self, metrics, monkeypatch) -> None:
        started: list[int] = []
        monkeypatch.setattr(
            prometheus_client, "start_http_server", lambda port: started.append(port)
        )
        monkeypatch.setattr(pm.settings, "worker_metrics_port", 9123)

        pm.setup_worker_metrics()

        assert started == [9123]
