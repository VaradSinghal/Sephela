# Kubernetes manifests

Implements the prod topology in [08-deployment.md](../../docs/architecture/08-deployment.md)
and the isolation requirements in [09-security.md](../../docs/architecture/09-security.md).

```
base/                    prod-shaped defaults, no image digest (not deployable alone)
overlays/{dev,staging,prod}/   pin the digest and adjust scale
deploy.sh                verify signature → render → migrate → apply → wait
```

## What has and has not been verified

**Verified in CI** (`backend/tests/test_k8s_manifests.py`, 54 checks): YAML parses;
every object names its namespace and is unique; Deployment selectors match their own
pod templates; Services select something; `envFrom` ConfigMaps/Secrets exist; every
`SEPHELA_*` key maps to a real `Settings` field; autoscaler targets exist and no
workload is scaled by both KEDA and an HPA; KEDA trigger secret keys are actually
provided; containers are non-root, non-privileged, cap-dropped, read-only-rootfs,
token-free and resource-limited; the sandbox isolation controls are present; both
namespaces default-deny; overlays pin digests.

**Not verified — needs a cluster.** No `kubectl`, `kustomize`, or cluster was
available when these were written, so the following are *unvalidated* and should be
expected to need correction on first apply:

- Server-side validation (`kubectl apply --dry-run=server`) — CRD schemas, admission
  webhooks, field-level types. `deploy.sh` runs this before applying.
- **CRD API versions.** `external-secrets.io/v1beta1` and `keda.sh/v1alpha1` are
  versioned by their operators and drift; check against the installed versions.
- **NetworkPolicy is only enforced if the CNI implements it.** On a cluster whose CNI
  ignores it, these objects apply cleanly and do nothing — the dangerous failure
  mode. Verify with a connectivity test, not `kubectl get netpol`.
- **`supplementalGroups: [108]`** in `dynamic-worker.yaml` is the `kvm` GID on a
  Debian-family node image. Wrong value → `/dev/kvm: permission denied` at emulator
  boot.
- **`devices.kubevirt.io/kvm`** assumes the KubeVirt device plugin. A different
  plugin uses a different resource name.
- Service DNS names assume Postgres/Redis/Qdrant run in a `sephela-data` namespace.
  Managed services need those `sephela-config` values repointed.

## Progressive delivery (opt-in, and not yet enabled)

`infra/k8s/components/canary/` holds an Argo Rollouts canary for the **API only**. Workers
are queue consumers with no inbound traffic to split — a bad worker build fails the tasks it
picks up regardless of how many replicas carry it — so their protection stays
`maxUnavailable: 0` plus the stage-failure metrics, which is the right shape for a consumer.

It is a kustomize *component* and **no overlay references it**. Enabling it makes that
overlay require an Argo Rollouts controller, so it stays opt-in until one is installed:

```yaml
# infra/k8s/overlays/prod/kustomization.yaml
components:
  - ../../components/canary
```

The design, and the two things most likely to be wrong on a first apply:

- **The pod template is not duplicated.** The Rollout adopts the existing Deployment through
  `workloadRef`, so the security context, probes, and resource limits stay in one place. A
  copy would drift out from under every posture check in the test suite, which only sees the
  manifests it is given.
- **Weights are approximate.** There is no service mesh, so both ReplicaSets sit behind the
  same Service and traffic splits by pod count. At 3 replicas the granularity is 33%, so
  `setWeight: 25` means one canary pod and roughly a third of the traffic. Precise weights
  need an SMI, Istio, or ALB `trafficRouting` provider.
- **`rollouts_pod_template_hash` must reach the application's metrics.** Every analysis query
  filters on it, and the app cannot add it — a pod does not know its own ReplicaSet hash. It
  comes from Prometheus relabeling pod labels onto scraped series. Without it every query
  returns the fleet average, the analysis passes whatever the canary is doing, and this is a
  rolling update wearing a canary's clothes. Verify with
  `sum by (rollouts_pod_template_hash) (http_requests_total)` returning more than one series
  during a rollout **before** trusting any of it.

The analysis gates on error rate, p95 latency, and readiness failures — all API-level, all
measurable within a canary window. It deliberately does not gate on risk scores or finding
counts: a canary runs for minutes and so does a job, so those have no meaningful sample in
that window and would either never trip or trip on noise. They belong on the Analysis
Quality dashboard, watched over hours.

## Cluster prerequisites

| Requirement | Why |
|---|---|
| CNI enforcing NetworkPolicy (Calico, Cilium) | Sandbox egress containment |
| External Secrets Operator + `ClusterSecretStore` named `vault-backend` | No secrets in git |
| KEDA | Queue-depth autoscaling |
| Node pool labelled `sephela.dev/workload=malware-sandbox`, tainted `sephela.dev/malware-sandbox` | Malware isolation |
| KubeVirt device plugin exposing `/dev/kvm` | Emulator |
| ingress-nginx + cert-manager (`letsencrypt-prod`) | TLS termination |
| Argo Rollouts controller — **only if** the canary component is enabled | Progressive delivery |
| Namespaces `sephela-data`, `observability`, `ingress-nginx` labelled with `kubernetes.io/metadata.name` | NetworkPolicy selectors |

## Deploying

```bash
make k8s-validate                     # parse + structural checks, no cluster needed
kustomize build infra/k8s/overlays/dev # inspect what would be applied
./infra/k8s/deploy.sh dev sha256:...  # verify signature → migrate → apply → wait
```

`deploy.sh` refuses a prod deploy it cannot verify a signature for, and pins the
digest with `kustomize edit` rather than `sed` so a malformed edit fails loudly.

## Two things that are easy to get wrong

**Migrations must be backward-compatible.** They run *before* the new pods roll out,
so during a rollout the old code is live against the new schema. A migration that
drops or renames a column in use breaks the still-running replicas. Additive first,
remove in a later release.

**The base intentionally has no `images:` block.** It carries `:latest`, so applying
it directly would ship an unpinned image; the overlays exist to prevent that, and a
test asserts the base stays that way.
