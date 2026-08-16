# Microservice Boundaries

Boundaries follow **domain responsibility + scaling profile + failure isolation**.
Services communicate only via contracts (`03-communication.md`). Malware-executing
components are isolated from everything else.

## Service catalog

### 1. API Gateway / Core Service (`backend/`)
- **Owns:** auth, RBAC, uploads intake, job lifecycle, report retrieval, health.
- **Does not:** run analysis. It validates, persists, and enqueues.
- **Scaling:** stateless; scale horizontally behind LB. CPU/IO light.
- **State:** PostgreSQL (system of record), Redis (cache/session), object storage.

### 2. Orchestration Worker (`workers/`)
- **Owns:** the analysis pipeline DAG — sequences engines, aggregates evidence,
  triggers scoring, invokes reporting, updates job state, publishes events.
- **Pattern:** each pipeline stage is a Celery task; stages are idempotent and
  resumable. Orchestrator = the pipeline definition, not a monolith.
- **Scaling:** horizontal by queue; separate worker pools per workload class
  (cpu-bound static, gpu/io dynamic, network-bound TI).

### 3. Static Analysis Engine (`engines/static/`) — Phase 5
- **Owns:** deterministic extraction from APK bytes (manifest, permissions, certs,
  strings, URLs/IPs, decompiled Java/Smali, obfuscation, packers).
- **Contract:** APK ref in → **Evidence Envelope** JSON out. Each extractor is an
  independent module; failure of one does not fail the engine.
- **Scaling:** CPU-bound pool; can become its own service via gRPC (`contracts/proto`).

### 4. Code Intelligence Engine (`engines/code_intel/`) — Phase 6
- **Owns:** turning decompiled output into compact, high-signal LLM context —
  strip framework/generated/third-party, detect developer code, call graphs,
  suspicious APIs, dangerous control flow, logical grouping, summaries.
- **Output:** token-minimized structured JSON consumed by the AI layer.

### 5. Dynamic Analysis Engine (`engines/dynamic/`) — Phase 10
- **Owns:** sandboxed runtime observation (emulator + Frida + mitmproxy),
  normalized runtime events. **Strictly isolated** — dedicated node pool, egress
  firewalled, ephemeral per-job VMs.
- **Scaling:** independent; expensive; queued separately; may be disabled per policy.

### 6. Threat Intelligence Engine (`engines/threat_intel/`) — Phase 11
- **Owns:** enrichment via external feeds (VT, OTX, AbuseIPDB, URLHaus, Bazaar);
  correlation of hashes/domains/IPs/certs/URLs/families. Caches aggressively;
  rate-limit aware; circuit-breakered.

### 7. GenAI / Multi-Agent Service (`ai/`) — Phase 7 → 13 ✅
- **Owns:** reasoning over evidence. Eight specialized agents (Manifest,
  Permission, Code, API, Network, TI, Risk, Report) run as nodes in a LangGraph
  state machine: the six analysis agents fan out in parallel from a single gate,
  fan in at a join barrier, then feed Risk and Report sequentially. RAG retrieval
  (Phase 12) feeds context. Routing policy lives in `ai/orchestration/router.py` —
  notably, a run whose analysis agents failed ≥50% aborts rather than scoring risk
  off half-missing evidence.
- **Durability:** agent calls are expensive and runs are long, so graph state is
  checkpointed per node; `PipelineRunner` resumes a half-finished job instead of
  re-running all eight agents.
- **Constraint:** consumes only Evidence Envelopes; emits validated structured
  findings with provenance. Cost/latency isolated from API path.

### 8. Risk Scoring Engine (`ai/scoring/`) — Phase 8
- **Owns:** hybrid, explainable score (deterministic weights + AI findings +
  signatures + TI). Emits score, severity, confidence, category, breakdown,
  MITRE/OWASP mapping. **No LLM call in the scoring math itself** — reproducible.

### 9. Reporting Engine (`reporting/`) — Phase 9
- **Owns:** rendering findings + score into JSON / Markdown / PDF for SOC/banking.

### 10. RAG / Knowledge Service (`ai/rag/`) — Phase 12
- **Owns:** vector DB, knowledge-base ingestion, semantic retrieval.

## Boundary rules
- One database schema owner per domain; no cross-service DB reads (access via API/events).
- Engines are **pure functions of their input** where possible (idempotent, cacheable by APK hash + engine version).
- Every engine emits the **same envelope shape** → the pipeline treats engines uniformly and new engines require zero orchestration changes.
