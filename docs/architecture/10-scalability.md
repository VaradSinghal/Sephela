# Future Scalability & Extensibility

The architecture is explicitly shaped so every roadmap capability slots in without
rearchitecting. Mapping of future requirement → enabling design decision:

| Future capability | Already enabled by |
|---|---|
| **Dynamic Analysis** (P10) | `q.dynamic` queue + isolated node pool reserved; Evidence Envelope already accommodates runtime findings; optional parallel pipeline branch. |
| **Threat Intelligence** (P11) | `q.threat_intel` + `enrichments` table + provider abstraction; runs in parallel group with AI; scoring already consumes TI verdicts. |
| **GenAI Orchestration** (P7) | `ai/` isolated service; LangGraph state machine; evidence-only inputs; structured-output validation. |
| **Vector Database / RAG** (P12) | Qdrant reserved; retrieval step already placed *before* LLM inference in DFD-3; knowledge-base ingestion pipeline slot. |
| **Multi-agent AI** (P13) ✅ | Landed as predicted: agents are pluggable LangGraph nodes mapping 1:1 to evidence domains, added without a pipeline change — the AI stage is one more entry in the Celery chain. |
| **Multiple malware engines** | Uniform Evidence Envelope + engine registry; adding an engine = new module + queue + pipeline entry, zero orchestration rewrite. |
| **Horizontal scaling** | Stateless API; per-workload queues; KEDA autoscaling; idempotent cacheable stages; partitioned tables. |

## Extensibility mechanisms
- **Engine registry + uniform contract.** Pipeline iterates a declarative list of
  enabled engines; new engine self-describes (name, version, queue, schema).
- **Pipeline as data.** `pipeline_version` records the exact engine set/order per
  job — enables A/B of pipelines, reproducibility, and gradual rollout.
- **Provider abstraction everywhere.** LLM, embeddings, TI feeds, object storage,
  broker all sit behind interfaces → swap/multi-provider without touching callers.
- **Prompt & scoring versioning.** Prompts and scoring weights are versioned
  artifacts; changes are traceable and A/B-testable.
- **Evidence caching.** `apk_sha256 + engine_version` cache → re-analysis and
  bulk campaigns cheap.

## Scaling dimensions & levers
| Dimension | Bottleneck | Lever |
|---|---|---|
| Ingest volume | API/intake | HPA on API, presigned direct-to-storage uploads |
| Static throughput | CPU | scale `w-static`, cache by hash |
| AI cost/latency | LLM tokens/RPM | code-intel token reduction, RAG relevance, prompt caching, batch, low concurrency + rate limit, smaller model routing for cheap sub-tasks |
| Dynamic capacity | emulator nodes | scale isolated pool, queue + priority, sample it (not every job) |
| TI rate limits | external APIs | cache + TTL, circuit breakers, per-provider budget |
| DB growth | evidence/findings | time-partitioning, archival to cold storage, read replicas |
| Vector scale | Qdrant | shard/replicate collections |

## Longer-horizon options (recorded, not committed)
- **gRPC engine services** (`contracts/proto`) if orchestration↔engine latency matters.
- **Temporal** if durable, versioned, long-running workflow state outgrows Celery.
- **Event sourcing / Kafka** if consumers of `job.*` events multiply (SIEM, lakes).
- **Model routing layer** to send cheap sub-tasks to smaller models, hard reasoning
  to frontier models — cost control at scale.
- **Multi-region** active-passive for DR / data-sovereignty.
