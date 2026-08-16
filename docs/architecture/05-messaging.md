# Message Queue Architecture

Celery + Redis (broker/result). RabbitMQ is the documented upgrade for durable,
complex routing at scale. The pipeline is a **DAG of idempotent stages**, each a
task, coordinated by Celery primitives (`chain`, `group`, `chord`) with DB-backed
state so runs are resumable and observable.

## Queue topology (by workload class)

| Queue | Workload | Worker pool | Concurrency model |
|---|---|---|---|
| `q.intake` | validation, hashing, dedup, persistence | light, many | prefork/threads |
| `q.static` | Androguard/JADX/APKID/YARA (CPU) | cpu-optimized | prefork, bounded |
| `q.code_intel` | preprocessing for LLM (CPU/mem) | mem-optimized | prefork |
| `q.ai` | LLM/agent calls (IO/network, costly) | io pool, rate-limited | gevent/async, low concurrency |
| `q.dynamic` | emulator sandbox (heavy, isolated) | dedicated isolated nodes | 1 job per sandbox |
| `q.threat_intel` | external API enrichment (network) | io pool, rate-limited | gevent |
| `q.scoring` | deterministic scoring | light | prefork |
| `q.reporting` | render json/md/pdf | light | prefork |
| `q.notify` | webhooks, events, emails | light | gevent |

Separate queues = independent scaling + isolation: a slow LLM or a stuck emulator
never starves fast static analysis.

## Pipeline (Phase-aware)

```
job.created
  └─ chain:
       intake (validate, sha256, dedup, store, persist sample+job)
       → static_analysis                     (Phase 5)
       → code_intelligence                   (Phase 6)
       → group( ai_analysis, threat_intel )  (Phases 7/11 run in parallel)
       → chord.callback: risk_scoring        (Phase 8, waits for the group)
       → reporting                           (Phase 9)
       → publish job.completed
   (dynamic_analysis is an optional parallel branch off intake — Phase 10,
    policy-gated; scoring waits on it via the chord when enabled)
```

**As implemented today** (`backend/app/tasks/pipeline.py`), the chain is
`dynamic → threat_intel → ai → finalize`, each stage gated by its own feature flag.
Two deliberate differences from the diagram above:

- `ai_analysis` is **chained after** `threat_intel` rather than grouped with it, so
  the threat-intel verdicts are in the envelope the agents reason over. Moving to
  `group()` is a one-line change if the ordering ever stops paying for itself.
- Risk scoring and reporting are not separate Celery stages: the multi-agent graph
  already ends in Risk → Report nodes (Phase 13), so a second orchestration hop
  would only re-load the same evidence.

Each stage:
1. Loads its inputs from DB/storage (never from the previous task's return payload
   beyond references) → **stateless, resumable**.
2. Writes a `stage_run` row (`running`), does work, writes evidence, sets status.
3. Updates `analysis_jobs.progress` and emits `job.stage.completed`.

## Reliability

- **Idempotency:** stage keyed by `(job_id, engine, engine_version)`. Re-runs
  upsert; safe to retry. Engine outputs cacheable by `apk_sha256 + engine_version`.
- **Retries:** exponential backoff, capped; distinguish *transient* (network, rate
  limit → retry) from *permanent* (corrupt APK → fail fast).
- **Timeouts:** per-stage soft/hard limits (`task_time_limit`); dynamic analysis
  has generous but bounded limits.
- **Dead-letter:** exhausted tasks → `q.dlq` + `job.failed` event + audit entry;
  never silently dropped.
- **Partial success:** an engine can return `partial`; pipeline continues; scoring
  notes reduced confidence. Missing evidence never crashes downstream.
- **Backpressure:** bounded prefetch (`worker_prefetch_multiplier=1` for heavy
  queues); autoscaling on queue depth (KEDA in K8s).
- **Poison-pill protection:** malformed messages rejected to DLQ, not re-looped.

## Observability
- Every message carries `job_id` + `trace_id`; propagated to logs + OTel spans.
- Metrics: queue depth, task latency, retry rate, failure rate per queue → Grafana.
- Flower (or custom) for live task inspection in non-prod.

## Scale path
Redis → RabbitMQ (quorum queues, publisher confirms) when durability/ordering
guarantees or complex topic routing outgrow Redis. Consider **Temporal** if
workflow versioning/long-running durable state becomes dominant (recorded in `10`).
