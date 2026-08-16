# Backup & Disaster Recovery

Covers the Phase-14 requirement in [08-deployment.md](../architecture/08-deployment.md):
PITR for Postgres, versioned and replicated object storage, Qdrant snapshots, stated
RTO/RPO, and a runbook that has actually been rehearsed.

**The load-bearing claim in this document is not the backup schedule — it is the
restore rehearsal.** An unrestored backup is a belief, not a control. Every schedule
below is paired with a verification step, and the game-day in the last section is
what makes the numbers real.

---

## What is being protected, and what "loss" means

The four stores fail differently, and conflating them leads to over-engineering the
cheap ones and under-protecting the expensive one.

| Store | Contents | If lost | Reconstructible? |
|---|---|---|---|
| **Postgres** | Jobs, stage runs, evidence envelopes, findings, users, audit trail | Analysis history and the audit trail — the compliance artifact | **No.** This is the irreplaceable store. |
| **Object storage** | APK bytes, dynamic-analysis artifacts | The samples themselves | **No**, unless the customer still holds the original upload. |
| **Redis** | Queues, rate-limit counters, caches | In-flight jobs | **Yes** — jobs are DB-driven and idempotent; re-dispatch from the DB. |
| **Qdrant** | RAG embeddings of the knowledge corpus | Retrieval quality until re-ingest | **Yes** — the corpus is in git; `make rag-ingest` rebuilds it. |

Only the first two need real backups. Redis and Qdrant need a documented
*rebuild path*, which is a materially cheaper thing to own — see below.

## Targets

| Environment | RPO (data you may lose) | RTO (time to serve again) |
|---|---|---|
| prod | ≤ 5 minutes | ≤ 1 hour |
| staging | ≤ 24 hours | ≤ 4 hours (best effort) |
| dev | none — expendable | rebuild from scratch |

The 5-minute prod RPO is what forces WAL archiving rather than nightly dumps: a
`pg_dump` at 02:00 has an RPO of up to 24 hours no matter how reliable it is.

---

## Postgres — PITR

Two independent mechanisms, because they fail independently: continuous WAL archiving
bounds the RPO, and a daily base backup bounds the *restore time* (replaying two
weeks of WAL to reach yesterday would blow the RTO).

```yaml
# CloudNativePG cluster spec (excerpt). The operator handles WAL shipping; what
# matters here is the retention and the destination being a different failure domain
# from the database.
spec:
  backup:
    barmanObjectStore:
      destinationPath: s3://sephela-backups/postgres
      s3Credentials:
        accessKeyId:     { name: backup-creds, key: ACCESS_KEY_ID }
        secretAccessKey: { name: backup-creds, key: SECRET_ACCESS_KEY }
      wal:
        compression: gzip
        maxParallel: 4        # keep archiving ahead of WAL generation under load
      data:
        compression: gzip
        immediateCheckpoint: false
    retentionPolicy: "30d"

  # Base backup daily; WAL ships continuously.
  # A backup bucket in the same region as the database survives a node or AZ loss
  # but not a region loss — cross-region replication on the bucket covers that.
```

**Restore to a point in time.** The timestamp is usually "one minute before the bad
migration", which is why the deploy log's timestamps matter.

```bash
# 1. Stop writers first. Restoring under live traffic produces a database that is
#    consistent with neither the backup nor the application.
kubectl scale deploy/sephela-api --replicas=0 -n sephela
kubectl scale deploy/w-static deploy/w-ai deploy/w-threat-intel --replicas=0 -n sephela
kubectl scale deploy/w-dynamic --replicas=0 -n sephela-sandbox

# 2. Restore into a NEW cluster. Never in place: if the restore is wrong you have
#    destroyed the only copy of the evidence.
kubectl apply -f - <<'EOF'
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: postgres-restored
  namespace: sephela-data
spec:
  instances: 3
  bootstrap:
    recovery:
      source: postgres-backup
      recoveryTarget:
        targetTime: "2026-08-16 09:14:00+00"   # ← the point to recover to
  externalClusters:
    - name: postgres-backup
      barmanObjectStore:
        destinationPath: s3://sephela-backups/postgres
        s3Credentials:
          accessKeyId:     { name: backup-creds, key: ACCESS_KEY_ID }
          secretAccessKey: { name: backup-creds, key: SECRET_ACCESS_KEY }
EOF

# 3. Verify BEFORE cutting over — see the verification queries below.
# 4. Repoint the app, then scale back up.
kubectl patch cm sephela-config -n sephela \
  --type merge -p '{"data":{"SEPHELA_POSTGRES_HOST":"postgres-restored-rw.sephela-data.svc.cluster.local"}}'
kubectl rollout restart deploy -n sephela
```

**Verification queries.** "The restore completed" is not "the restore is good".

```sql
-- Alembic revision must match the application image being deployed. A mismatch here
-- is the difference between a working restore and a subtly broken schema.
SELECT version_num FROM alembic_version;

-- Recency: how much did we actually lose? Compare against the incident start.
SELECT max(created_at) AS newest_job FROM analysis_jobs;
SELECT max(created_at) AS newest_audit FROM audit_logs;

-- Referential sanity: evidence orphaned from its job means a partial restore.
SELECT count(*) FROM evidence e
  LEFT JOIN analysis_jobs j ON j.id = e.job_id WHERE j.id IS NULL;   -- expect 0

-- The audit trail is the compliance artifact; a gap in it is reportable.
SELECT date_trunc('hour', created_at) AS hour, count(*)
  FROM audit_logs
 WHERE created_at > now() - interval '48 hours'
 GROUP BY 1 ORDER BY 1;   -- look for missing hours
```

**Jobs left mid-flight.** Restored `running` jobs correspond to workers that no
longer exist. Stages are idempotent and DB-driven, so re-dispatch is safe:

```sql
-- Inspect first.
SELECT id, status, created_at FROM analysis_jobs WHERE status = 'running';
-- Then requeue: the pipeline re-reads state from the DB and skips completed stages.
UPDATE analysis_jobs SET status = 'queued', started_at = NULL WHERE status = 'running';
```

## Object storage — samples and artifacts

Versioning plus replication, and a lifecycle policy that is a *retention* decision
rather than a storage-cost one.

```json
{
  "Rules": [
    {
      "Id": "cross-region-replication",
      "Comment": "A region loss must not lose the samples. The DB backup bucket and this one should not share a region.",
      "Status": "Enabled",
      "Destination": { "Bucket": "arn:aws:s3:::sephela-samples-dr", "StorageClass": "STANDARD_IA" }
    },
    {
      "Id": "versioning-guards-against-deletion",
      "Comment": "Object Lock in governance mode: ransomware or a bad script cannot delete a sample, only add a delete marker.",
      "Status": "Enabled"
    },
    {
      "Id": "artifact-expiry",
      "Comment": "Dynamic-analysis artifacts came from a machine that ran malware and are only needed while the report is fresh. Samples themselves follow the per-org retention policy, NOT this rule.",
      "Prefix": "dynamic-artifacts/",
      "Expiration": { "Days": 90 }
    }
  ]
}
```

> **Retention is a contractual question, not an ops one.** Per-org retention and
> secure deletion are required by [09-security.md](../architecture/09-security.md).
> Do not shorten sample retention to save storage without the customer agreement
> that governs it.

## Redis — rebuild, do not restore

No backup. Persistence is enabled only to survive a restart, and a restored Redis is
actively worse than an empty one: it would re-dispatch jobs the DB already shows as
complete.

```bash
# After a Redis loss: start empty, then requeue from the DB (the query above).
# Rate-limit counters rebuild themselves within one window.
```

## Qdrant — snapshot, but treat git as the source of truth

```bash
# Nightly snapshot to object storage — a convenience for fast recovery.
curl -X POST "http://qdrant.sephela-data:6333/collections/sephela_knowledge/snapshots"

# Authoritative rebuild path. Slower, but it cannot restore a corrupt index and it
# needs no backup to have worked.
kubectl run rag-ingest --rm -it \
  --image="$IMAGE" --namespace sephela \
  --overrides='{"spec":{"containers":[{"name":"rag-ingest","image":"'"$IMAGE"'","command":["python","-m","ai.rag"],"envFrom":[{"configMapRef":{"name":"sephela-config"}},{"secretRef":{"name":"sephela-secrets"}}]}]}}'
```

---

## Scenario playbooks

### A bad migration corrupted data

RTO target: 1 hour. Roll the schema back only if the migration has a tested
`downgrade`; otherwise PITR to just before it ran.

1. Scale writers to zero (step 1 above) — stop the damage spreading.
2. `SELECT version_num FROM alembic_version;` to confirm what actually applied.
3. PITR to one minute before the migration's timestamp in the deploy log.
4. Verify, cut over, then redeploy the *previous* image digest — the new image
   expects the new schema.

### Region loss

RTO target: 4 hours (exceeds the 1-hour prod target; this is a stated,
accepted gap for a full-region event, not an oversight).

1. Restore Postgres into the DR region from the replicated backup bucket.
2. Repoint the app at the replicated sample bucket (`sephela-samples-dr`).
3. Rebuild Redis empty and Qdrant from the corpus — neither is replicated, by design.
4. Requeue in-flight jobs.
5. Update DNS. **Expect the RPO to be worse than 5 minutes here**: cross-region
   replication is asynchronous, so the last WAL segments may not have shipped.

### The audit trail has a gap

Treat as a security incident, not an ops one. `audit_logs` is append-only with
`UPDATE`/`DELETE` revoked from the app role (migration `0004`), so a gap means either
the write path failed (look for `audit_write_failed` in logs — writes are
deliberately non-fatal so an audit outage cannot reject a bank's upload) or someone
used credentials beyond the app role. Both are reportable; establish which before
restoring anything, because a restore overwrites the evidence.

### Suspected sandbox escape

1. Cordon the node: `kubectl cordon <node>` — do not delete the pod, it is evidence.
2. `kubectl scale deploy/w-dynamic --replicas=0 -n sephela-sandbox`.
3. Snapshot the node for forensics before it is reclaimed.
4. The blast radius is bounded by design (dedicated tainted pool, no egress, no
   service-account token, one sample per pod) — verify each of those held rather
   than assuming it.
5. Nothing else needs restoring: the sandbox holds no durable state.

---

## Game-day rehearsal — quarterly, and the reason this document is trustworthy

A backup that has never been restored is not a backup. Run this against **staging**,
whose topology matches prod, and record the measured numbers.

```
[ ] Restore prod's latest base backup + WAL into a scratch cluster
[ ] Run every verification query above; record the measured RPO
[ ] Time the whole restore end to end; record the measured RTO
[ ] Requeue in-flight jobs and confirm one completes
[ ] Restore a deleted object from a versioned bucket
[ ] Rebuild Qdrant from the corpus and confirm retrieval returns results
[ ] Update the table below — including when the numbers got worse
```

| Date | Scenario | Measured RPO | Measured RTO | Notes |
|---|---|---|---|---|
| _(pending)_ | — | — | — | No rehearsal has been run yet. **The RTO/RPO targets above are therefore design intent, not measured facts**, and should not be quoted to a customer as achieved until this table has an entry. |
