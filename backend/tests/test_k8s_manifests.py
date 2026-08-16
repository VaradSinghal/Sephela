"""Structural validation of the Kubernetes manifests in infra/k8s.

There is no cluster in CI, so these do not prove the manifests *deploy*. They check
the class of mistake that a cluster would only reveal at 3am: a Deployment whose
selector does not match its own pods, a Service selecting nothing, an envFrom
pointing at a ConfigMap that was renamed, a KEDA trigger reading a secret key nobody
provides (which fails silently — the autoscaler just never scales), and the
security posture that the sandbox isolation depends on.

`kubectl apply --dry-run=server` and a real connectivity test are still required
before trusting any of this; see infra/k8s/README.md.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

_BASE = Path(__file__).resolve().parents[2] / "infra" / "k8s" / "base"
_OVERLAYS = Path(__file__).resolve().parents[2] / "infra" / "k8s" / "overlays"


def _load(directory: Path) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text()):
            if doc:
                doc["__file__"] = path.name
                docs.append(doc)
    return docs


@pytest.fixture(scope="module")
def manifests() -> list[dict[str, Any]]:
    docs = _load(_BASE)
    assert docs, f"no manifests found under {_BASE}"
    return [d for d in docs if d.get("kind") != "Kustomization"]


def _ns(doc: dict[str, Any]) -> str | None:
    return (doc.get("metadata") or {}).get("namespace")


def _name(doc: dict[str, Any]) -> str | None:
    return (doc.get("metadata") or {}).get("name")


def _of(manifests: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [d for d in manifests if d.get("kind") == kind]


def _pod_specs(manifests: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    """Every pod template in the manifest set, keyed by owner name."""
    out = []
    for d in manifests:
        if d.get("kind") in ("Deployment", "Job", "StatefulSet", "DaemonSet"):
            out.append((str(_name(d)), d["spec"]["template"]["spec"]))
    return out


class TestWellFormed:
    def test_every_document_declares_kind_and_apiversion(self, manifests) -> None:
        for d in manifests:
            assert d.get("apiVersion"), f"{d['__file__']}: missing apiVersion"
            assert d.get("kind"), f"{d['__file__']}: missing kind"

    def test_every_namespaced_object_names_its_namespace(self, manifests) -> None:
        # Relying on kubectl's `--namespace` default is how objects land in the wrong
        # namespace; the sandbox separation depends on this being explicit.
        for d in manifests:
            if d["kind"] in ("Namespace", "ClusterSecretStore"):
                continue
            assert _ns(d), f"{d['__file__']}: {d['kind']}/{_name(d)} has no namespace"

    def test_object_identities_are_unique(self, manifests) -> None:
        seen: set[tuple[str, str | None, str | None]] = set()
        for d in manifests:
            key = (d["kind"], _name(d), _ns(d))
            assert key not in seen, f"duplicate object {key}"
            seen.add(key)


class TestSelectors:
    def test_each_deployment_selects_its_own_pods(self, manifests) -> None:
        for d in _of(manifests, "Deployment"):
            selector = (d["spec"].get("selector") or {}).get("matchLabels") or {}
            labels = (d["spec"]["template"].get("metadata") or {}).get("labels") or {}
            assert selector, f"{_name(d)}: no selector"
            for key, value in selector.items():
                assert labels.get(key) == value, (
                    f"{_name(d)}: selector {key}={value} not on its pod template"
                )

    def test_each_service_selects_something(self, manifests) -> None:
        deployments = _of(manifests, "Deployment")
        for svc in _of(manifests, "Service"):
            selector = svc["spec"].get("selector") or {}
            matched = any(
                _ns(dep) == _ns(svc)
                and all(
                    ((dep["spec"]["template"].get("metadata") or {}).get("labels") or {}).get(k)
                    == v
                    for k, v in selector.items()
                )
                for dep in deployments
            )
            assert matched, f"Service {_name(svc)} selector matches no pod: {selector}"


class TestReferences:
    def test_envfrom_configmaps_and_secrets_exist(self, manifests) -> None:
        configmaps = {(_ns(d), _name(d)) for d in _of(manifests, "ConfigMap")}
        secrets = {
            (_ns(d), (d["spec"].get("target") or {}).get("name") or _name(d))
            for d in _of(manifests, "ExternalSecret")
        }
        for d in manifests:
            if d["kind"] not in ("Deployment", "Job"):
                continue
            for container in d["spec"]["template"]["spec"]["containers"]:
                for source in container.get("envFrom", []):
                    if "configMapRef" in source:
                        key = (_ns(d), source["configMapRef"]["name"])
                        assert key in configmaps, f"{_name(d)}: missing ConfigMap {key}"
                    if "secretRef" in source:
                        key = (_ns(d), source["secretRef"]["name"])
                        assert key in secrets, f"{_name(d)}: missing Secret {key}"

    def test_autoscaler_targets_exist(self, manifests) -> None:
        deployments = {(_ns(d), _name(d)) for d in _of(manifests, "Deployment")}
        for d in _of(manifests, "ScaledObject") + _of(manifests, "HorizontalPodAutoscaler"):
            target = (_ns(d), d["spec"]["scaleTargetRef"]["name"])
            assert target in deployments, f"{_name(d)} targets missing Deployment {target}"

    def test_no_workload_is_scaled_by_both_keda_and_an_hpa(self, manifests) -> None:
        # Two controllers writing `spec.replicas` oscillate against each other.
        keda = {
            (_ns(d), d["spec"]["scaleTargetRef"]["name"]) for d in _of(manifests, "ScaledObject")
        }
        hpa = {
            (_ns(d), d["spec"]["scaleTargetRef"]["name"])
            for d in _of(manifests, "HorizontalPodAutoscaler")
        }
        assert not (keda & hpa), f"scaled by both: {keda & hpa}"

    def test_keda_trigger_secret_keys_are_provided(self, manifests) -> None:
        # A missing key does not error — KEDA fails to authenticate and silently
        # never scales, which looks like "the queue is just slow".
        provided = {
            (_ns(d), (d["spec"].get("target") or {}).get("name") or _name(d)): {
                entry["secretKey"] for entry in d["spec"]["data"]
            }
            for d in _of(manifests, "ExternalSecret")
        }
        for d in _of(manifests, "TriggerAuthentication"):
            for ref in d["spec"]["secretTargetRef"]:
                keys = provided.get((_ns(d), ref["name"]), set())
                assert ref["key"] in keys, (
                    f"TriggerAuthentication {_name(d)} in {_ns(d)} needs "
                    f"{ref['key']!r} from {ref['name']}, which does not provide it"
                )

    def test_the_secret_keys_map_to_real_settings(self, manifests) -> None:
        # A renamed setting would otherwise be injected under a name the app ignores,
        # and the app would fall back to its default — for SEPHELA_SECRET_KEY that
        # means refusing to boot, which is the good case; for others it means running
        # misconfigured.
        from app.core.config import Settings

        fields = {f"SEPHELA_{name.upper()}" for name in Settings.model_fields}
        # Not every injected variable is a Settings field: the LLM SDK reads its own.
        exempt = {"ANTHROPIC_API_KEY"}
        for d in _of(manifests, "ExternalSecret"):
            for entry in d["spec"]["data"]:
                key = entry["secretKey"]
                if key in exempt:
                    continue
                assert key in fields, f"{key} is not a Settings field"

    def test_configmap_keys_map_to_real_settings(self, manifests) -> None:
        from app.core.config import Settings

        fields = {f"SEPHELA_{name.upper()}" for name in Settings.model_fields}
        for d in _of(manifests, "ConfigMap"):
            for key in d.get("data", {}):
                if not key.startswith("SEPHELA_"):
                    continue
                assert key in fields, f"{_name(d)}: {key} is not a Settings field"


class TestSecurityPosture:
    def test_the_main_namespace_enforces_restricted_pod_security(self, manifests) -> None:
        main = next(d for d in _of(manifests, "Namespace") if _name(d) == "sephela")
        labels = main["metadata"]["labels"]
        assert labels["pod-security.kubernetes.io/enforce"] == "restricted"

    def test_no_container_runs_as_root(self, manifests) -> None:
        for name, spec in _pod_specs(manifests):
            ctx = spec.get("securityContext") or {}
            assert ctx.get("runAsNonRoot") is True, f"{name}: runAsNonRoot not set"

    def test_no_container_allows_privilege_escalation(self, manifests) -> None:
        for name, spec in _pod_specs(manifests):
            for container in spec["containers"]:
                ctx = container.get("securityContext") or {}
                assert ctx.get("allowPrivilegeEscalation") is False, (
                    f"{name}/{container['name']}: privilege escalation not denied"
                )

    def test_no_container_is_privileged(self, manifests) -> None:
        # Privileged disables seccomp and grants every capability — the one thing
        # standing between a sandbox escape and the node.
        for name, spec in _pod_specs(manifests):
            for container in spec["containers"]:
                ctx = container.get("securityContext") or {}
                assert not ctx.get("privileged"), f"{name}/{container['name']} is privileged"

    def test_every_container_drops_all_capabilities(self, manifests) -> None:
        for name, spec in _pod_specs(manifests):
            for container in spec["containers"]:
                caps = (container.get("securityContext") or {}).get("capabilities") or {}
                assert caps.get("drop") == ["ALL"], f"{name}/{container['name']}: caps not dropped"

    def test_root_filesystems_are_read_only(self, manifests) -> None:
        for name, spec in _pod_specs(manifests):
            for container in spec["containers"]:
                ctx = container.get("securityContext") or {}
                assert ctx.get("readOnlyRootFilesystem") is True, (
                    f"{name}/{container['name']}: writable root filesystem"
                )

    def test_no_workload_mounts_a_service_account_token(self, manifests) -> None:
        # None of these components call the Kubernetes API, so a mounted token is
        # only useful to an attacker who lands in the pod.
        for name, spec in _pod_specs(manifests):
            assert spec.get("automountServiceAccountToken") is False, (
                f"{name}: service-account token is mounted"
            )

    def test_every_container_declares_resource_limits(self, manifests) -> None:
        # Without limits one runaway decompile can evict its neighbours.
        for name, spec in _pod_specs(manifests):
            for container in spec["containers"]:
                resources = container.get("resources") or {}
                assert resources.get("requests"), f"{name}/{container['name']}: no requests"
                assert resources.get("limits"), f"{name}/{container['name']}: no limits"


class TestSandboxIsolation:
    """The controls that keep a sample that escapes its emulator contained."""

    @pytest.fixture
    def sandbox(self, manifests) -> dict[str, Any]:
        return next(d for d in _of(manifests, "Deployment") if _name(d) == "w-dynamic")

    def test_it_runs_in_its_own_namespace(self, sandbox) -> None:
        assert _ns(sandbox) == "sephela-sandbox"

    def test_it_is_pinned_to_the_tainted_malware_node_pool(self, sandbox) -> None:
        spec = sandbox["spec"]["template"]["spec"]
        assert spec["nodeSelector"]["sephela.dev/workload"] == "malware-sandbox"
        assert any(t["key"] == "sephela.dev/malware-sandbox" for t in spec["tolerations"])

    def test_two_sandboxes_never_share_a_node(self, sandbox) -> None:
        anti = sandbox["spec"]["template"]["spec"]["affinity"]["podAntiAffinity"]
        assert anti["requiredDuringSchedulingIgnoredDuringExecution"]

    def test_each_pod_analyses_exactly_one_sample(self, sandbox) -> None:
        # A compromised emulator process must not be reused for the next job.
        args = sandbox["spec"]["template"]["spec"]["containers"][0]["args"]
        assert "--max-tasks-per-child=1" in args
        assert "--concurrency=1" in args

    def test_it_consumes_only_the_dynamic_queue(self, sandbox) -> None:
        args = sandbox["spec"]["template"]["spec"]["containers"][0]["args"]
        assert "--queues=dynamic" in args

    def test_it_holds_no_llm_or_threat_intel_credentials(self, manifests) -> None:
        # It produces evidence; it does not reason about it.
        secret = next(d for d in _of(manifests, "ExternalSecret") if _ns(d) == "sephela-sandbox")
        keys = {entry["secretKey"] for entry in secret["spec"]["data"]}
        assert not {k for k in keys if "ANTHROPIC" in k or "VIRUSTOTAL" in k or "BAZAAR" in k}

    def test_artifacts_do_not_outlive_the_pod(self, sandbox) -> None:
        volumes = {v["name"]: v for v in sandbox["spec"]["template"]["spec"]["volumes"]}
        assert "emptyDir" in volumes["artifacts"], "sandbox artifacts must not persist"


class TestNetworkPolicy:
    def test_both_namespaces_default_deny_ingress_and_egress(self, manifests) -> None:
        # Every other policy is meaningless without these.
        policies = _of(manifests, "NetworkPolicy")
        for namespace in ("sephela", "sephela-sandbox"):
            deny = [
                p
                for p in policies
                if _ns(p) == namespace
                and not (p["spec"].get("podSelector") or {})
                and set(p["spec"]["policyTypes"]) == {"Ingress", "Egress"}
            ]
            assert deny, f"{namespace}: no default-deny policy"

    def test_dns_is_explicitly_allowed(self, manifests) -> None:
        # Otherwise every hostname lookup fails and presents as "Postgres is down".
        policies = _of(manifests, "NetworkPolicy")
        assert any(
            any(
                port.get("port") == 53
                for rule in p["spec"].get("egress", [])
                for port in rule.get("ports", [])
            )
            for p in policies
        )

    def test_the_sandbox_is_never_granted_internet_egress(self, manifests) -> None:
        # A sample that reaches its C2 from inside the analysis environment leaks the
        # bank's exposure and taints the capture.
        for policy in _of(manifests, "NetworkPolicy"):
            if _ns(policy) != "sephela-sandbox":
                continue
            for rule in policy["spec"].get("egress", []):
                for destination in rule.get("to", []):
                    assert "ipBlock" not in destination, (
                        f"{_name(policy)} grants the sandbox an ipBlock egress rule"
                    )

    def test_internet_egress_excludes_the_cloud_metadata_endpoint(self, manifests) -> None:
        # 169.254.169.254 hands out node credentials to anything that can reach it.
        for policy in _of(manifests, "NetworkPolicy"):
            for rule in policy["spec"].get("egress", []):
                for destination in rule.get("to", []):
                    block = destination.get("ipBlock")
                    if not block or block.get("cidr") != "0.0.0.0/0":
                        continue
                    assert any(
                        "169.254.169.254" in excluded for excluded in block.get("except", [])
                    ), f"{_name(policy)}: metadata endpoint reachable"


class TestOverlays:
    @pytest.mark.parametrize("env", ["dev", "staging", "prod"])
    def test_each_overlay_parses_and_builds_on_the_base(self, env: str) -> None:
        doc = yaml.safe_load((_OVERLAYS / env / "kustomization.yaml").read_text())
        assert doc["kind"] == "Kustomization"
        assert "../../base" in doc["resources"]

    @pytest.mark.parametrize("env", ["staging", "prod"])
    def test_deployed_environments_pin_an_image_digest(self, env: str) -> None:
        # A tag is mutable: the same tag before and after a force-push is two
        # different images, which breaks both rollback and signature verification.
        doc = yaml.safe_load((_OVERLAYS / env / "kustomization.yaml").read_text())
        for image in doc["images"]:
            assert image.get("digest"), f"{env}: {image['name']} is not pinned by digest"
            assert not image.get("newTag"), f"{env}: {image['name']} uses a mutable tag"

    def test_the_base_is_not_deployable_by_itself(self) -> None:
        # The base carries `:latest`, so applying it directly would ship an
        # unpinned image. Overlays exist to prevent that.
        doc = yaml.safe_load((_BASE / "kustomization.yaml").read_text())
        assert "images" not in doc

    def test_dev_disables_dynamic_analysis(self) -> None:
        # There is no KVM node pool in dev, so jobs would queue against a pool that
        # will never have capacity.
        text = (_OVERLAYS / "dev" / "kustomization.yaml").read_text()
        assert "SEPHELA_DYNAMIC_ENABLED" in text
        assert "w-dynamic" in text
