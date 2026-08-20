# Grafana dashboards & Prometheus rules

Three dashboards, because they answer three different questions and merging any two of
them produces something nobody reads during an incident.

| Dashboard | Question | Open it when |
|---|---|---|
| [Pipeline Health](dashboards/pipeline-health.json) | Is the pipeline keeping up, and where is it failing? | First, always |
| [Analysis Quality](dashboards/analysis-quality.json) | Is what it produces worth trusting? | After a scoring or engine change |
| [LLM Cost & Latency](dashboards/llm-cost.json) | What is the multi-agent stage costing? | Monthly, and after any prompt change |

Alerting and recording rules are in [rules/sephela-alerts.yaml](rules/sephela-alerts.yaml).

## What is validated, and what is not

`make dashboards-validate` runs [37 checks](../../backend/tests/test_dashboards.py) with
no Grafana and no Prometheus involved. The one that earns its place:

> **Every metric a panel or an alert queries must be one the application actually emits.**

That is checkable because `app.core.pipeline_metrics.metric_names()` enumerates what the
code can produce, and it catches the failure mode a running Grafana never reports — a
renamed metric leaves a permanently empty panel, and an empty panel on a health dashboard
reads as *no problems here*. An alert on a metric nothing emits is worse: it is
indistinguishable from the condition never occurring.

The rest is structural: unique UIDs (provisioning keys on them, so a collision silently
replaces one dashboard with another), every panel having a target, every alert having a
severity label and a description longer than a restatement of its own expression, and every
`runbook:` annotation pointing at a file that exists.

**These do not prove a dashboard renders.** Panel layout, legend formatting, and whether a
heatmap is readable all need a Grafana. Import them once by hand before relying on them.

## Two conventions worth knowing before editing

**Adding a metric means editing two places.** Register the collector in
`app/core/pipeline_metrics.py` *and* add its name to `metric_names()`. A metric absent from
that set cannot be queried by any panel — the test will reject it — and one present but
never registered would let a broken panel pass. `test_pipeline_metrics.py` asserts the two
agree in both directions.

**Skipped stages and partial jobs are never alerts.** Dynamic analysis and the AI stage are
off by default, so both are the *expected* outcome on a stock install; an alert on either
would fire permanently and train everyone to ignore the channel. They are dashboard panels
on Analysis Quality instead, where the signal is a *change* — a stage that starts being
skipped when it was not before. Two tests enforce this, because it is exactly the kind of
alert that looks obviously correct when you add it.

Every ratio in the rules guards its denominator with `clamp_min`, and every alert has a
`for` window. Without both, one failed job on a quiet system produces a 100% failure rate
and a page. A test enforces that too.

## Where the metrics come from

The API exposes `/metrics` from its ASGI app when `SEPHELA_METRICS_ENABLED=true`.

Celery workers cannot do that — they serve no HTTP — so each one starts its own exporter on
`SEPHELA_WORKER_METRICS_PORT` (9100) when it becomes ready, found through the same
`prometheus.io/scrape` pod annotation the API uses. Queue depth is the one metric no task
can report, because no task knows how many others are behind it; `health.publish_queue_depth`
samples the broker from beat instead.

So a deployment scraping only the API sees the HTTP metrics and none of the pipeline ones,
and most of these panels will be empty. That is the most likely reason for an empty
dashboard on a first install.

## Provisioning

Grafana file provisioning, sidecar, or `grafana_dashboard` Terraform resources all work —
the JSON is plain dashboard JSON with a `${datasource}` variable rather than a hardcoded
UID, so it imports against any Prometheus datasource.

```yaml
# /etc/grafana/provisioning/dashboards/sephela.yaml
apiVersion: 1
providers:
  - name: sephela
    type: file
    options:
      path: /var/lib/grafana/dashboards/sephela
```

The rule file goes wherever your Prometheus `rule_files` glob points, or into a
`PrometheusRule` custom resource if you run the operator.
