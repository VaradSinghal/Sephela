# Load testing

Closes the Phase-14 item in [11-dev-standards.md](../../docs/architecture/11-dev-standards.md):
"Load | locust/k6 (staging) | meet throughput SLOs".

That row named a tool and a gate but never defined the SLOs, so this document defines
them. **They are proposals calibrated against the architecture's design targets, not
measured facts** — nothing here has been run against a deployed environment. The first
real run should adjust these numbers and say so; a threshold nobody has ever met is
worse than no threshold, because the first failing run gets waved through.

## Service level objectives

| Endpoint class | Metric | Target | Why this number |
|---|---|---|---|
| Job status / findings reads | p95 latency | < 500 ms | A SOC dashboard polls these; above ~500 ms the UI feels stalled. |
| Job status / findings reads | p99 latency | < 1500 ms | Bounds the tail without demanding the p99 match the p95. |
| Reads | sustained throughput | ≥ 150 rps | ~50 concurrent analysts polling every 2 s, with 3× headroom. |
| Upload accept (202) | p95 latency | < 2 s | The endpoint only validates, stores, and enqueues — analysis is async. A rising p95 points at storage or the DB commit, not at the pipeline. |
| Upload accept (202) | p99 latency | < 5 s | Allows for a 300 MiB body on a slow link. |
| Errors (excluding 429) | rate | < 1% reads / < 2% uploads | Uploads get more room because they touch storage. |
| Availability during a rollout | — | no failed requests | `maxUnavailable: 0` plus the readiness gate should make deploys invisible. |

**Queue drain, not request latency, is the real upload SLO.** The API returns 202 in
milliseconds regardless of how deep the backlog is, so upload latency alone will look
healthy while the pipeline falls arbitrarily far behind. `upload-soak.js` samples
queued-job count for exactly this reason: a maximum that climbs monotonically across
the run means ingest is outpacing the workers.

## Two interactions that will otherwise invalidate a run

**Rate limiting.** The API limits per authenticated principal (300 req/min, 20/min
for uploads). A test driving one account flatlines at the budget and measures the
limiter rather than the platform. The harness spreads load across seeded accounts and
counts 429s as their own metric, excluded from the error rate — a 429 means a
protective control worked, and scoring it as a failure makes a healthy run look
broken.

**Cost.** With `SEPHELA_AI_ENABLED=true`, every upload triggers an eight-agent LLM
run. A 10-minute soak at 30 uploads/min is ~300 runs of real spend. With
`SEPHELA_DYNAMIC_ENABLED=true`, every upload boots an emulator and will exhaust the
KVM node pool long before the API is stressed. Leave both off unless the run exists
to measure them, and know which you are paying for before you start.

## Seeding

There is no self-service registration, so the accounts must be provisioned:

```bash
ORG=$(python -m app.cli create-org "Load Test" | awk '/id:/{print $2}')
export SEPHELA_INITIAL_PASSWORD='<a strong password>'
for i in $(seq 0 19); do
  python -m app.cli create-user "loadtest+$i@sephela.test" --org-id "$ORG" --role analyst
done
```

The accounts are `analyst` because that is the least privilege that can upload. They
share one org, so the tenant-scoping filters behave as they would for one customer.

## Running

```bash
export SEPHELA_URL=https://api.staging.sephela.example
export SEPHELA_LOAD_PASSWORD='<the same password>'

make load-read     # steady-state read mix — the release gate
make load-upload   # low-rate upload soak — watch queue depth, not latency
```

Knobs: `SEPHELA_LOAD_USERS` (default 20), `SEPHELA_LOAD_UPLOAD_RATE` (per minute,
default 30), `SEPHELA_LOAD_DURATION` (default `10m`), `SEPHELA_LOAD_APK_KB` (payload
padding, default 64).

Thresholds are encoded in each scenario's `options.thresholds`, so a breach exits
non-zero and the script works as a gate rather than a report.

## Staging only

`make load-read` against prod is a self-inflicted denial of service, and the upload
soak would fill a real customer's tenant with synthetic jobs. Staging is
prod-shaped by design (see the `staging` overlay) for precisely this.

## Reading a result

| Symptom | Likely cause |
|---|---|
| Read p95 fine, p99 spiking | GC or connection-pool contention; check PgBouncer saturation. |
| Read latency climbs with VUs, CPU flat | Postgres connection limit — the API is waiting on a pool, not working. |
| `sephela_rate_limited` high, latency fine | The limiter is mis-sized for this traffic shape. A finding about configuration, not health. |
| Upload accept p95 climbing | Storage write or the DB commit before enqueue — not the analysis pipeline. |
| Queue depth max climbing monotonically | Workers cannot keep up. Scale the pools or lower the arrival rate. |
| 5xx during a rollout | The readiness probe is passing before the app can serve; check its `initialDelaySeconds`. |
