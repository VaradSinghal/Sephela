# Sephela Threat Intelligence Engine (Phase 11)

Enriches the indicators that static and dynamic analysis surfaced against external
threat feeds, correlates the answers across providers, and emits a standardized
**Evidence Envelope** for the scoring and AI layers.

```
IoCs (hash / domain / ip / url / cert)
  → cache lookup (Postgres, TTL per indicator class)
  → rate-limited provider calls (circuit-breakered)
  → cross-provider correlation
  → Evidence Envelope
```

## Providers

| Provider | Indicators | Key | Notes |
|---|---|---|---|
| `bazaar` (MalwareBazaar) | hash | optional | Curated malware family names — the highest-signal feed for "is this APK a known banking trojan?" |
| `urlhaus` | url, domain, ip | none | Malware *distribution* URLs. Keyless, so a zero-config deployment still produces real evidence. |
| `virustotal` | hash, domain, ip, url | required | Multi-engine AV consensus. Tightest free quota (4 req/min). |
| `otx` (AlienVault) | hash, domain, ip, url | required | Community pulses → campaign and actor attribution. |
| `abuseipdb` | ip | required | Crowd-sourced abuse confidence for IP infrastructure. |

A provider without its key is **omitted**, not failed — coverage degrades, the
stage still succeeds.

## Design guarantees

- **Pure function of its inputs.** Indicators and providers in, envelope out. The
  engine owns no database and reads no configuration; the caller supplies the
  cache (the backend backs it with the `enrichments` table).
- **Failure is partial, never fatal.** A rate-limited or unreachable feed becomes
  an entry in `envelope.errors` and degrades the status to `partial`. Only a run
  where *no* provider produced anything is `failed`.
- **Cost is bounded in layers**: cache → global `max_lookups` ceiling →
  per-provider token bucket. Truncation is always disclosed in `errors`, because
  a silently shortened run would read as "nothing found".
- **A dead feed costs one timeout, not one per indicator.** The circuit breaker
  drops a provider for the rest of the run after repeated failures.
- **Stable finding ids**, derived from the indicator rather than iteration order,
  so stage retries upsert instead of duplicating.

## Usage

```python
from sephela_threat_intel import analyze, build_providers, iocs_from_findings, sample_iocs

iocs = sample_iocs(sha256=sample.sha256, md5=sample.md5)
iocs += iocs_from_findings(finding_rows)          # url/ip/cert/network findings

envelope = await analyze(
    iocs,
    providers=build_providers({"virustotal": VT_KEY}),
    cache=cache,                                  # EnrichmentCache protocol
    max_lookups=200,
)
```

## Tests

```bash
cd engines/threat_intel && pytest
```

No test touches the network: providers are driven through `httpx.MockTransport`,
and the rate limiter and circuit breaker take an injected clock.

## Contracts

- Envelope: `docs/architecture/03-communication.md`
- `enrichments` table: `docs/architecture/04-data-model.md`
- Queue + partial-success policy: `docs/architecture/05-messaging.md`
- Service boundary: `docs/architecture/02-services.md` §6
