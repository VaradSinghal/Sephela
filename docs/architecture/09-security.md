# Security Considerations

This platform **stores and executes malware** for **banks**. Security is the
architecture, not a layer. Threat model below (STRIDE-oriented) + controls.

## Trust boundaries
1. Internet ↔ API Gateway (untrusted input, auth boundary).
2. API ↔ internal services (authenticated service mesh).
3. Analysis workers ↔ **malware** (the sample is hostile — assume RCE attempts).
4. Platform ↔ external TI/LLM providers (data-egress boundary).

## The malware-handling threat (most critical)
- **Sandbox escape / RCE from a crafted APK.** Controls:
  - Dynamic analysis on isolated, tainted node pool; ephemeral VMs; **egress
    default-deny**; destroyed post-run.
  - Static engines: unprivileged, read-only FS, seccomp/AppArmor, **no network**,
    strict CPU/mem/time limits, no shell-out with untrusted args.
  - APKs stored **encrypted at rest**, never executed outside sandbox, never served
    to browsers; downloads are analyst-gated + audited.
  - Decompiled artifacts treated as untrusted data; never `eval`'d/rendered raw.
- **Prompt injection via APK content** (strings/code fed to LLM):
  - Evidence is passed as clearly delimited *data*, never as instructions.
  - System prompts instruct agents to treat sample content as untrusted and never
    follow embedded instructions. Structured-output schema constrains responses.
  - Retrieved RAG docs are trusted-source only; sample-derived text is quarantined.

## STRIDE controls
| Threat | Control |
|---|---|
| **Spoofing** | OIDC/SSO, JWT with short TTL + refresh rotation, mTLS between services |
| **Tampering** | Immutable jobs/audit; signed webhooks (HMAC); integrity hashes on artifacts |
| **Repudiation** | Append-only `audit_logs` (actor, action, target, ip, ts) |
| **Info disclosure** | Encryption in transit (TLS 1.3) + at rest; RBAC + per-org row isolation; secrets in Vault |
| **DoS** | Per-org rate limits, upload size caps, queue backpressure, resource quotas per job |
| **Elevation** | Least-privilege RBAC (admin/analyst/viewer), no ambient service creds, scoped tokens |

## AuthN / AuthZ

**Implemented (Phase 14)** — `backend/app/core/security.py`:

- **Local credentials**, bcrypt with a SHA-256 pre-hash so passphrases over 72 bytes
  are not silently truncated to a shared prefix. Access tokens are short; refresh
  tokens rotate on every use and are type-checked, so a refresh token cannot be
  presented as an access token.
- **The token is an identifier, not a source of truth.** `role` and `org_id` are read
  from the `users` row on every request, never from a claim. A signed token asserting
  `role: admin` on another tenant is inert, and deactivating a user takes effect on
  their next request rather than when their token expires.
- **RBAC** as an ordered ladder (`viewer < analyst < admin`): viewers read status and
  findings; analyst+ is required to upload, cancel, or read raw evidence envelopes
  (which carry decompiled strings and captured traffic from live malware); admin
  reads the audit trail.
- **Multi-tenant isolation** by passing `org_id` into the repository rather than
  filtering after the fetch — a missed check is then a missing argument rather than a
  forgotten `if`. Another tenant's job returns **404, not 403**: confirming that a
  job exists is itself a disclosure.
- **No user enumeration** at login — unknown email, wrong password, and disabled
  account return one identical 401, and the unknown-email path still burns a hash
  comparison so the timing matches.
- **Append-only `audit_logs`** with `UPDATE`/`DELETE` revoked from the app role
  (migration `0004`), covering logins (failures included, committed even though the
  request errors), uploads, evidence access, and cancellations.
- **Per-principal rate limits** (Redis; tighter bucket for uploads) and a streaming
  upload cap, so a multi-gigabyte POST cannot exhaust a pod's memory before the size
  check runs.
- **Boot-time refusal** to run any non-`local` environment on placeholder secrets.

**Remaining**: enterprise OIDC/SAML SSO — the seam exists (`PrincipalResolver`,
`register_resolver`), so a provider plugs in behind the same `get_current_user`
dependency without touching route signatures. PostgreSQL Row-Level Security is not
yet enabled, so app-layer scoping is the single enforcement point today rather than
the intended defence in depth.

There is no self-service registration, by design — tenants are banks. Provisioning is
an operator action: `python -m app.cli bootstrap "Bank" admin@bank.example`.

## Data governance
- Data classification: APK bytes = "hostile/confidential"; reports = "confidential".
- Retention policies per org; secure deletion; audit of exports.
- PII: banking samples may embed PII/creds in strings → redact in reports, restrict
  raw string access, log access.
- **Egress control:** hashes/IOCs sent to external TI feeds by policy; sending the
  *full APK* to third parties (e.g. VT upload) is **opt-in per org** and audited —
  default is hash-only lookups to avoid leaking a bank's samples.

## Secrets & supply chain
- Vault / K8s ExternalSecrets; no secrets in images, env files, or git.
- SBOM generation; dependency + container scanning in CI; pinned digests; signed
  images (cosign); admission control (only signed images run).
- Network policies: default-deny, explicit allowlists between services.

## Compliance posture
Designed toward SOC 2 / ISO 27001 / PCI-DSS-adjacent controls: audit trails,
encryption, access control, change management, DR. (Formal certification = program,
not just architecture.)
