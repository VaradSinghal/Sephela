"""Domain metrics for the analysis pipeline.

``app.core.metrics`` covers the API's HTTP surface and is registered from a FastAPI
app. These are different: the stages that produce them run in **Celery workers**, which
serve no HTTP at all, so ``setup_metrics(app)`` never runs there and its collectors are
never created. A worker therefore has to start its own exporter — see
``setup_worker_metrics`` — and the worker Deployment carries the same
``prometheus.io/scrape`` annotation the API does.

Everything here is a no-op when metrics are disabled or ``prometheus_client`` is absent,
matching ``app.core.metrics``. That is deliberate rather than lazy: instrumentation that
can fail a stage is worse than no instrumentation, because the stage is the thing that
produces the analysis and the metric only describes it.

Cardinality is the other constraint. Every label here is drawn from a closed set —
engine names, statuses, severities, queue names, model ids, agent names — so no label
value can be attacker-influenced. A job id or a package name as a label would grow the
series count without bound, which takes Prometheus down rather than the app.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from app.core.config import settings
from app.core.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Mapping

logger = get_logger(__name__)

#: Every collector, keyed by metric name. Populated by ``_register`` and left empty when
#: metrics are off, which is what makes each ``observe``/``inc`` below a cheap no-op.
_METRICS: dict[str, Any] = {}
_REGISTERED = False

#: A stage lasts from seconds (scoring) to many minutes (decompiling a large APK), so the
#: buckets span three orders of magnitude. The 300/600 boundaries matter most: they
#: bracket the Celery soft time limits, which is where a stage stops being slow and
#: starts being killed.
_STAGE_DURATION_BUCKETS = (0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 1200)

#: Risk scores are 0–100 and the tier boundaries are what a dashboard reads, so the
#: buckets follow them rather than being evenly spaced.
_RISK_SCORE_BUCKETS = (10, 20, 30, 40, 50, 60, 70, 80, 90, 100)

#: An LLM call is seconds to a couple of minutes; the tail is what a canary gate watches.
_LLM_DURATION_BUCKETS = (1, 2.5, 5, 10, 20, 30, 60, 120, 300)


def _register() -> None:
    """Create the collectors once. Safe to call repeatedly and from any process."""
    global _REGISTERED  # noqa: PLW0603
    if _REGISTERED:
        return
    _REGISTERED = True

    if not settings.metrics_enabled:
        logger.info("pipeline_metrics_disabled")
        return

    try:
        from prometheus_client import Counter, Gauge, Histogram
    except ImportError:
        logger.warning(
            "pipeline_metrics_import_failed",
            detail="prometheus_client not installed; pipeline metrics disabled",
        )
        return

    _METRICS.update(
        {
            # ---- Jobs ----
            "jobs_total": Counter(
                "sephela_jobs_total",
                "Analysis jobs that reached a terminal state, by outcome",
                ["status"],
            ),
            "job_duration_seconds": Histogram(
                "sephela_job_duration_seconds",
                "End-to-end wall-clock time of a job, from intake to finalize",
                buckets=_STAGE_DURATION_BUCKETS,
            ),
            # ---- Stages ----
            "stage_total": Counter(
                "sephela_stage_total",
                "Stage executions by engine and terminal status",
                ["stage", "status"],
            ),
            "stage_duration_seconds": Histogram(
                "sephela_stage_duration_seconds",
                "Stage execution time in seconds",
                ["stage"],
                buckets=_STAGE_DURATION_BUCKETS,
            ),
            "stage_retries_total": Counter(
                "sephela_stage_retries_total",
                "Stage executions that were not the first attempt",
                ["stage"],
            ),
            # ---- Analysis output ----
            "findings_total": Counter(
                "sephela_findings_total",
                "Findings persisted, by producing engine and severity",
                ["stage", "severity"],
            ),
            "risk_score": Histogram(
                "sephela_risk_score",
                "Distribution of final risk scores",
                buckets=_RISK_SCORE_BUCKETS,
            ),
            "risk_tier_total": Counter(
                "sephela_risk_tier_total",
                "Scored jobs by risk tier",
                ["tier"],
            ),
            # ---- Queues ----
            "queue_depth": Gauge(
                "sephela_queue_depth",
                "Messages waiting on a Celery queue",
                ["queue"],
            ),
            # ---- LLM ----
            "llm_tokens_total": Counter(
                "sephela_llm_tokens_total",
                "Tokens consumed, by model and agent",
                ["model", "agent"],
            ),
            "llm_calls_total": Counter(
                "sephela_llm_calls_total",
                "LLM calls by model, agent, and outcome",
                ["model", "agent", "outcome"],
            ),
            "llm_call_duration_seconds": Histogram(
                "sephela_llm_call_duration_seconds",
                "LLM call latency in seconds",
                ["model", "agent"],
                buckets=_LLM_DURATION_BUCKETS,
            ),
        }
    )
    logger.info("pipeline_metrics_enabled", count=len(_METRICS))


def metric_names() -> frozenset[str]:
    """Every Prometheus metric name this module can emit.

    Exists so ``tests/test_dashboards.py`` can check that no dashboard panel queries a
    metric nothing produces — a renamed metric otherwise leaves a permanently empty
    panel that looks like "no problems here".
    """
    return frozenset(
        {
            "sephela_jobs_total",
            "sephela_job_duration_seconds",
            "sephela_stage_total",
            "sephela_stage_duration_seconds",
            "sephela_stage_retries_total",
            "sephela_findings_total",
            "sephela_risk_score",
            "sephela_risk_tier_total",
            "sephela_queue_depth",
            "sephela_llm_tokens_total",
            "sephela_llm_calls_total",
            "sephela_llm_call_duration_seconds",
        }
    )


def _collector(name: str) -> Any | None:
    if not _REGISTERED:
        _register()
    return _METRICS.get(name)


# ---------------------------------------------------------------------------
# Recording helpers. Each one is a no-op when metrics are off.
# ---------------------------------------------------------------------------


def record_job(status: str, *, duration_seconds: float | None = None) -> None:
    """A job reached a terminal state."""
    if (counter := _collector("jobs_total")) is not None:
        counter.labels(status=status).inc()
    if duration_seconds is not None and (h := _collector("job_duration_seconds")) is not None:
        h.observe(duration_seconds)


def record_stage(
    stage: str,
    status: str,
    *,
    duration_seconds: float | None = None,
    attempt: int = 1,
) -> None:
    """A stage reached a terminal state.

    ``skipped`` is recorded like any other status rather than omitted: how often a
    deployment runs partial is one of the more useful things to know about it, and an
    absent series cannot answer that.
    """
    if (counter := _collector("stage_total")) is not None:
        counter.labels(stage=stage, status=status).inc()
    if duration_seconds is not None and (h := _collector("stage_duration_seconds")) is not None:
        h.labels(stage=stage).observe(duration_seconds)
    if attempt > 1 and (retries := _collector("stage_retries_total")) is not None:
        retries.labels(stage=stage).inc()


def record_findings(stage: str, severities: Mapping[str, int]) -> None:
    """Findings a stage persisted, counted by severity."""
    counter = _collector("findings_total")
    if counter is None:
        return
    for severity, count in severities.items():
        if count:
            counter.labels(stage=stage, severity=severity).inc(count)


def record_risk(score: float, tier: str) -> None:
    """The scoring stage's verdict."""
    if (h := _collector("risk_score")) is not None:
        h.observe(max(0.0, min(100.0, score)))
    if (counter := _collector("risk_tier_total")) is not None:
        counter.labels(tier=tier).inc()


def set_queue_depth(queue: str, depth: int) -> None:
    """Messages waiting on one queue. Published by a periodic task, not per message."""
    if (gauge := _collector("queue_depth")) is not None:
        gauge.labels(queue=queue).set(depth)


def record_llm_call(
    *,
    model: str,
    agent: str,
    outcome: str,
    tokens: int = 0,
    duration_seconds: float | None = None,
) -> None:
    """One LLM call. ``tokens`` is what makes a paid credential's cost observable."""
    if (counter := _collector("llm_calls_total")) is not None:
        counter.labels(model=model, agent=agent, outcome=outcome).inc()
    if tokens and (t := _collector("llm_tokens_total")) is not None:
        t.labels(model=model, agent=agent).inc(tokens)
    if duration_seconds is not None and (h := _collector("llm_call_duration_seconds")) is not None:
        h.labels(model=model, agent=agent).observe(duration_seconds)


# ---------------------------------------------------------------------------
# Worker exporter
# ---------------------------------------------------------------------------


def setup_worker_metrics() -> None:
    """Start a metrics endpoint inside a Celery worker.

    A worker has no ASGI app to hang ``/metrics`` off, so it runs a minimal HTTP server
    of its own on ``settings.worker_metrics_port``. Prometheus finds it through the same
    pod annotation the API uses.

    Never raises. A worker that cannot bind the port must still process jobs; losing
    metrics is a monitoring gap, while failing to start is an outage.
    """
    _register()
    if not settings.metrics_enabled or not _METRICS:
        return

    try:
        from prometheus_client import start_http_server

        start_http_server(settings.worker_metrics_port)
        logger.info("worker_metrics_server_started", port=settings.worker_metrics_port)
    except Exception as exc:  # noqa: BLE001 — see the docstring
        logger.warning("worker_metrics_server_failed", error=str(exc))
