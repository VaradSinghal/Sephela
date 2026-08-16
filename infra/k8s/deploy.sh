#!/usr/bin/env bash
# Apply one overlay at a pinned image digest.
#
#   ./infra/k8s/deploy.sh <dev|staging|prod> <sha256:...>
#
# Lives as a script rather than inline workflow YAML so the same steps run from a
# laptop during an incident, when GitHub Actions is not the thing you want in the
# path. It expects kubectl on PATH and either an active context or KUBECONFIG_B64.
#
# The digest is required, not optional. Deploying a tag would mean the thing that
# ran in staging and the thing that runs in prod are only *probably* the same image.
set -euo pipefail

ENVIRONMENT="${1:?usage: deploy.sh <dev|staging|prod> <image-digest>}"
DIGEST="${2:?missing image digest (sha256:...)}"

REGISTRY="${REGISTRY:-ghcr.io}"
IMAGE_NAME="${IMAGE_NAME:-${GITHUB_REPOSITORY:-sephela/sephela}/backend}"
IMAGE="${REGISTRY}/${IMAGE_NAME}"
OVERLAY="infra/k8s/overlays/${ENVIRONMENT}"
NAMESPACES=(sephela sephela-sandbox)

case "$ENVIRONMENT" in
  dev|staging|prod) ;;
  *) echo "unknown environment: $ENVIRONMENT" >&2; exit 2 ;;
esac
[[ -d "$OVERLAY" ]] || { echo "no overlay at $OVERLAY" >&2; exit 2; }
[[ "$DIGEST" == sha256:* ]] || { echo "digest must start with sha256: — got '$DIGEST'" >&2; exit 2; }

if [[ -n "${KUBECONFIG_B64:-}" ]]; then
  KUBECONFIG="$(mktemp)"
  export KUBECONFIG
  # shellcheck disable=SC2064
  trap "rm -f '$KUBECONFIG'" EXIT
  base64 -d <<<"$KUBECONFIG_B64" > "$KUBECONFIG"
fi

echo "==> deploying ${IMAGE}@${DIGEST} to ${ENVIRONMENT}"

# Refuse to deploy an unsigned image. This is defence in depth behind cluster
# admission control: if admission is misconfigured, this still stops the rollout,
# and it fails here (visibly, in the deploy log) rather than as an ImagePullBackOff.
if command -v cosign >/dev/null 2>&1; then
  echo "==> verifying signature"
  cosign verify \
    --certificate-identity-regexp "^https://github.com/${GITHUB_REPOSITORY:-.*}/" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "${IMAGE}@${DIGEST}" >/dev/null
else
  echo "!! cosign not found — skipping signature verification" >&2
  [[ "$ENVIRONMENT" == "prod" ]] && { echo "refusing unverified prod deploy" >&2; exit 3; }
fi

# Pin the digest into the overlay. `kustomize edit` rather than sed so a malformed
# edit fails loudly instead of producing valid-looking YAML with the wrong image.
( cd "$OVERLAY" && kustomize edit set image "${IMAGE}@${DIGEST}" )

echo "==> rendering manifests"
kustomize build "$OVERLAY" > /tmp/sephela-rendered.yaml

# Server-side dry run validates against the live API (CRDs, admission webhooks,
# field types) — the checks a local YAML parse cannot do.
echo "==> server-side dry run"
kubectl apply --dry-run=server -f /tmp/sephela-rendered.yaml

# Migrations first and separately: the workloads must not start against an
# un-migrated schema. Delete-then-recreate because a completed Job is immutable.
echo "==> running migrations"
kubectl delete job sephela-migrate -n sephela --ignore-not-found
kubectl apply -f <(awk '/kind: Job/,0' /tmp/sephela-rendered.yaml) -n sephela
kubectl wait --for=condition=complete job/sephela-migrate -n sephela --timeout=10m

echo "==> applying manifests"
kubectl apply -f /tmp/sephela-rendered.yaml

echo "==> waiting for rollouts"
for namespace in "${NAMESPACES[@]}"; do
  # `kubectl rollout status` exits non-zero on timeout, which fails the deploy —
  # that is the point. A deploy that "succeeded" while pods crash-loop is worse
  # than one that reports failure.
  while read -r deployment; do
    [[ -n "$deployment" ]] || continue
    echo "    $namespace/$deployment"
    kubectl rollout status "$deployment" -n "$namespace" --timeout=10m
  done < <(kubectl get deployments -n "$namespace" -o name 2>/dev/null || true)
done

echo "==> deployed ${DIGEST} to ${ENVIRONMENT}"
