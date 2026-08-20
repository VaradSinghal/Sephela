"""The contract every agent must satisfy, applied to all eight of them.

Per-agent files cover per-agent logic. This file covers the part that must not vary:
each agent is constructible with a client, builds a prompt from the shared evidence
envelope without raising, calls the gateway with its own model and schema, and turns
a schema-shaped response into a validated model.

That last point is the one worth stating plainly. Every agent's ``parse_output`` is
the same ``json.loads`` / code-fence-regex / ``Schema(**data)`` boilerplate, so a
break in the shared path in ``BaseAgent`` would break all eight identically — which
is exactly the failure mode that went unnoticed until now. Parametrising over the
real agent classes means a single run covers all of them.
"""

from __future__ import annotations

from typing import Any

import pytest

from ai.agents.api import APIAgent
from ai.agents.base import AgentStatus
from ai.agents.code import CodeAgent
from ai.agents.manifest import ManifestAgent
from ai.agents.network import NetworkAgent
from ai.agents.permission import PermissionAgent
from ai.agents.report import ReportAgent
from ai.agents.risk import RiskAgent
from ai.agents.threat_intel import ThreatIntelAgent

# A response that satisfies each agent's schema with the least possible content, so
# a failure here is about the plumbing rather than about the payload.
_MINIMAL_REPORT = {
    "report_id": "r-1",
    "job_id": "j-1",
    "sample_sha256": "a" * 64,
    "executive_summary": {"overview": "Nothing of note.", "risk_score": 1.0, "risk_tier": "benign"},
    "technical_details": {},
    "evidence_catalog": {},
    "compliance_mapping": {},
}

# ``RiskBreakdown.model_post_init`` asserts the factors reconcile to ``final_score``,
# so the factor here is load-bearing rather than decoration.
_MINIMAL_RISK = {
    "score": 42.0,
    "tier": "suspicious",
    "confidence": 0.7,
    "breakdown": {
        "factors": [
            {
                "factor_id": "perm-1",
                "name": "Accessibility service",
                "category": "permissions",
                "weight": 0.42,
                "raw_score": 100.0,
                "weighted_contribution": 42.0,
            }
        ],
        "base_score": 42.0,
        "final_score": 42.0,
        "computed_at": "2026-01-01T00:00:00Z",
        "confidence": 0.7,
    },
}

#: (label, agent class, a response body its schema accepts). The classes are typed
#: loosely because each concrete agent's ``__init__`` takes only ``llm_client``,
#: while ``BaseAgent.__init__`` requires a config it builds internally.
AGENTS: list[tuple[str, Any, dict[str, Any]]] = [
    ("manifest", ManifestAgent, {"package_name": "com.example.test"}),
    ("permission", PermissionAgent, {"total_permissions": 3}),
    ("code", CodeAgent, {}),
    ("api", APIAgent, {}),
    ("network", NetworkAgent, {"domains": ["example.com"]}),
    ("threat_intel", ThreatIntelAgent, {"total_ioc_matches": 0}),
    ("risk", RiskAgent, _MINIMAL_RISK),
    ("report", ReportAgent, {"report": _MINIMAL_REPORT, "generation_time_ms": 12}),
]

_IDS = [label for label, _, _ in AGENTS]
_CASES = [(cls, payload) for _, cls, payload in AGENTS]


@pytest.mark.parametrize(("agent_cls", "payload"), _CASES, ids=_IDS)
class TestEveryAgent:
    def test_it_declares_a_name_and_an_output_schema(
        self, agent_cls: Any, payload: dict[str, Any]
    ) -> None:
        # BaseAgent._validate_config refuses either being absent, so construction
        # succeeding is the assertion; these two make the intent legible.
        agent = agent_cls()
        assert agent.config.name
        assert agent.config.output_schema is not None

    def test_it_builds_a_prompt_from_the_shared_evidence_envelope(
        self, agent_cls: Any, payload: dict[str, Any], sample_evidence: dict[str, Any]
    ) -> None:
        prompt = agent_cls().build_prompt(sample_evidence, {})
        assert prompt.strip()

    def test_it_builds_a_prompt_from_an_empty_envelope(
        self, agent_cls: Any, payload: dict[str, Any]
    ) -> None:
        # A stage can be skipped or fail, so an agent must tolerate its evidence key
        # being absent rather than KeyError-ing the whole graph.
        assert agent_cls().build_prompt({}, {}).strip()

    async def test_it_calls_the_gateway_with_its_own_model_and_schema(
        self,
        agent_cls: Any,
        payload: dict[str, Any],
        gateway_for: Any,
        sample_evidence: dict[str, Any],
    ) -> None:
        gateway = gateway_for(payload)
        agent = agent_cls(llm_client=gateway)

        await agent.execute(sample_evidence, {})

        (call,) = gateway.calls
        assert call["model_name"] == agent.config.model
        assert call["response_schema"] is agent.config.output_schema

    async def test_a_schema_shaped_response_produces_a_validated_output(
        self,
        agent_cls: Any,
        payload: dict[str, Any],
        gateway_for: Any,
        sample_evidence: dict[str, Any],
    ) -> None:
        agent = agent_cls(llm_client=gateway_for(payload))

        result = await agent.execute(sample_evidence, {})

        assert result.status is AgentStatus.completed, result.errors
        assert isinstance(result.output, agent.config.output_schema)
        assert result.tokens_used == 512

    async def test_a_fenced_response_is_recovered_rather_than_retried(
        self,
        agent_cls: Any,
        payload: dict[str, Any],
        gateway_for: Any,
        sample_evidence: dict[str, Any],
    ) -> None:
        # Models wrap JSON in ```json fences constantly. The validator strips them,
        # so this must not cost an extra turn.
        import json

        fenced = f"```json\n{json.dumps(payload)}\n```"
        gateway = gateway_for(fenced)

        result = await (agent_cls(llm_client=gateway)).execute(sample_evidence, {})

        assert result.status is AgentStatus.completed, result.errors
        assert len(gateway.calls) == 1

    async def test_findings_extraction_never_raises(
        self,
        agent_cls: Any,
        payload: dict[str, Any],
        gateway_for: Any,
        sample_evidence: dict[str, Any],
    ) -> None:
        result = await (agent_cls(llm_client=gateway_for(payload))).execute(sample_evidence, {})

        assert isinstance(result.findings, list)


def test_every_agent_has_a_distinct_name() -> None:
    # The orchestrator keys graph state by agent name, so a collision would have one
    # agent's result silently overwrite another's.
    names = [cls().config.name for _, cls, _ in AGENTS]
    assert len(names) == len(set(names)), names
