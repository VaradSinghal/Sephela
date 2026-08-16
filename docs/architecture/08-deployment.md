# Deployment Architecture

## Environments
| Env | Purpose | Infra |
|---|---|---|
| local | dev full-stack | `docker-compose` (all services + MinIO + Postgres + Redis) |
| dev | integration | K8s namespace, ephemeral data |
| staging | pre-prod, load/security tests | K8s, prod-like, synthetic samples |
| prod | live | K8s, HA, autoscaled, backups+DR |

## Kubernetes topology (prod)

```
                     ┌───────── Ingress (TLS, WAF) ─────────┐
                     ▼                                       
             ┌───────────────┐   HPA (cpu/rps)               
             │ api-gateway    │  (stateless, N replicas)     
             └───────┬───────┘                               
   ┌─────────────────┼──────────────────────────────────┐   
   ▼                 ▼                                    ▼   
┌────────┐   ┌──────────────┐                    ┌──────────────┐
│Postgres│   │   Redis       │                    │ Object Store │
│ (HA,    │   │ (broker+cache)│                    │ (S3/MinIO)   │
│ replica)│   └──────────────┘                    └──────────────┘
└────────┘                                                        
   Worker pools (separate Deployments, KEDA-autoscaled on queue depth):
   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────────┐
   │ w-static │ │w-code_int│ │  w-ai    │ │ w-tintel │ │  w-dynamic     │
   │ (cpu)    │ │ (mem)    │ │(io,ratel)│ │(io,ratel)│ │ ISOLATED node  │
   └──────────┘ └──────────┘ └──────────┘ └──────────┘ │ pool, no egress│
                                                        └────────────────┘
   ┌──────────┐  ┌──────────┐   ┌─────────────────────────────────────┐
   │w-scoring │  │w-report  │   │ Qdrant (vector DB, Phase 12)        │
   └──────────┘  └──────────┘   └─────────────────────────────────────┘
   Observability: Prometheus, Grafana, Loki, OTel Collector, Alertmanager
```

## Isolation of malware-executing workloads (critical)
- **`w-dynamic`** runs on a **dedicated, tainted node pool** — no other workloads.
- **Egress denied by default** (NetworkPolicy); only explicit sink for capture.
- **Ephemeral sandboxes**: one job → one emulator VM → destroyed after.
- Static engines also run **unprivileged, read-only rootfs, seccomp/AppArmor,
  no network** (they only parse bytes).

## Scaling strategy
- API: HPA on RPS/CPU; stateless → linear scale.
- Workers: **KEDA** scales each pool on its queue depth independently.
- Postgres: primary + read replicas; PgBouncer pooling; partition large tables
  (`evidence`, `findings`, `audit_logs`) by time.
- Redis: managed/HA; move to RabbitMQ for durability at scale.
- Object storage: effectively unbounded.

## CI/CD (Phase 14) ✅
Two workflows, split by what they need rather than by convenience:

- **`ci.yml`** — correctness. Runs on every PR including forks, so it holds no
  credentials: lint, format, mypy, unit tests + coverage floor, bandit/pip-audit,
  import boundaries, engine suites, the AI suite, and manifest validation.
- **`release.yml`** — delivery. Needs registry and cluster credentials, so it never
  runs from a fork PR: `build+push by digest → SBOM + provenance attestation → Trivy
  scan (blocking on CRITICAL/HIGH) → cosign keyless sign → deploy`.

The ordering is the security property: an image is scanned *before* it is signed, and
only a signed **digest** is deployed. Signing first would attest to something nobody
checked; deploying a tag would let a later force-push swap the contents out from under
the signature. Environments gate progressively — dev on `main`, staging after dev,
prod only from a `v*` tag behind a GitHub Environment required-reviewer rule (kept
there rather than in the workflow file, so it cannot be removed by editing YAML).

`infra/k8s/deploy.sh` runs the same steps from a laptop during an incident: verify
signature → `kustomize edit set image` → `apply --dry-run=server` → migration Job →
apply → `rollout status`. It refuses an unverifiable prod deploy.

Migrations run as a pre-deploy Job and **must be backward-compatible** — during a
rollout the old code is live against the new schema, so a dropped or renamed column
breaks the still-running replicas. Additive first, remove in a later release.

Progressive delivery (canary for the API, blue/green for workers) is **not yet
implemented**: the current strategy is a `maxUnavailable: 0` rolling update.

## Backup & DR (Phase 14) ✅ documented, ⚠️ unrehearsed
Full runbook: [docs/runbooks/backup-and-dr.md](../runbooks/backup-and-dr.md).

- **Postgres** — continuous WAL archiving (bounds RPO) + daily base backups (bounds
  restore time) to object storage, 30-day retention. Restore is always into a *new*
  cluster, never in place.
- **Object storage** — versioning with Object Lock, cross-region replication.
- **Redis** — no backup by design. A restored Redis is worse than an empty one: it
  would re-dispatch jobs the DB already shows complete. Requeue from the DB instead.
- **Qdrant** — nightly snapshots for speed, but git is the source of truth; the
  authoritative recovery is `make rag-ingest`.
- **Targets**: prod RPO ≤ 5 min, RTO ≤ 1 h. A full region loss has a stated,
  accepted RTO of ~4 h.

> The RTO/RPO numbers above are **design intent, not measured facts** — no game-day
> has been run. The runbook's rehearsal table is empty, and these figures should not
> be quoted to a customer as achieved until it has an entry.
