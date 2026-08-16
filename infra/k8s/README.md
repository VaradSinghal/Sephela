# Kubernetes manifests

Implements the prod topology in [08-deployment.md](../../docs/architecture/08-deployment.md)
and the isolation requirements in [09-security.md](../../docs/architecture/09-security.md).

```
base/                    prod-shaped defaults, no image digest (not deployable alone)
overlays/{dev,staging,prod}/   pin the digest and adjust scale
deploy.sh                verify signature → render → migrate → apply → wait
```

## What has and has not been verified

**Verified in CI** (`backend/tests/test_k8s_manifests.py`, 37 checks): YAML parses;
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

## Cluster prerequisites

| Requirement | Why |
|---|---|
| CNI enforcing NetworkPolicy (Calico, Cilium) | Sandbox egress containment |
| External Secrets Operator + `ClusterSecretStore` named `vault-backend` | No secrets in git |
| KEDA | Queue-depth autoscaling |
| Node pool labelled `sephela.dev/workload=malware-sandbox`, tainted `sephela.dev/malware-sandbox` | Malware isolation |
| KubeVirt device plugin exposing `/dev/kvm` | Emulator |
| ingress-nginx + cert-manager (`letsencrypt-prod`) | TLS termination |
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
