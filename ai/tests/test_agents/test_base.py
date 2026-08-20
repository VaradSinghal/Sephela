"""Tests for BaseAgent's LLM call path.

This file exists because of what it did not catch. ``_call_llm`` shipped as an
unconditional ``raise NotImplementedError`` and no agent overrode it, so every
agent's ``execute()`` died on the first turn — and nothing failed, because the
orchestration tests swap the agents for stubs and this directory was empty. The
tests below pin the seam those two facts left open: that an agent, given a client,
actually calls it, with the right parameters, and does something sensible with what
comes back.

No network and no provider SDK: the clients here are the two shapes ``_call_llm``
accepts, written out by hand so the assertions are about the contract rather than
about a mock's configuration.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel

from ai.agents.base import AgentConfig, AgentStatus, BaseAgent

# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class Out(BaseModel):
    """Minimal agent output schema."""

    verdict: str
    confidence: float = 0.5


class _Usage:
    def __init__(self, total: int) -> None:
        self.total_tokens = total


class _GenerateResult:
    """Shape of ai.llm.factory.GenerateResult, as far as _call_llm reads it."""

    def __init__(self, content: str, tokens: int = 0) -> None:
        self.content = content
        self.usage = _Usage(tokens)


class GatewayDouble:
    """An ``LLMGateway``-shaped client: exposes ``generate(**kwargs)``."""

    def __init__(self, *responses: str, tokens: int = 1234) -> None:
        self._responses = list(responses) or ['{"verdict": "clean"}']
        self._tokens = tokens
        self.calls: list[dict[str, Any]] = []

    async def generate(self, **kwargs: Any) -> _GenerateResult:
        self.calls.append(kwargs)
        # Repeat the last response once exhausted, so a retry test can supply
        # fewer responses than there are attempts.
        content = self._responses[min(len(self.calls) - 1, len(self._responses) - 1)]
        return _GenerateResult(content, tokens=self._tokens)


class _LLMResponse:
    """Shape of ai.llm.client.LLMResponse, as far as _call_llm reads it."""

    def __init__(self, content: str, tokens_used: int) -> None:
        self.content = content
        self.tokens_used = tokens_used


class ClientDouble:
    """An ``LLMClient``-shaped client: exposes ``complete(prompt)`` only."""

    def __init__(self, content: str = '{"verdict": "clean"}', tokens: int = 77) -> None:
        self._content = content
        self._tokens = tokens
        self.prompts: list[str] = []

    async def complete(self, prompt: str) -> _LLMResponse:
        self.prompts.append(prompt)
        return _LLMResponse(self._content, self._tokens)


class ProbeAgent(BaseAgent[Out]):
    """Concrete agent with the smallest possible prompt and parser."""

    def __init__(self, llm_client: Any = None, **overrides: Any) -> None:
        defaults: dict[str, Any] = {
            "name": "probe_agent",
            "model": "claude-opus-5",
            "temperature": 0.25,
            "max_tokens": 1024,
            "timeout_seconds": 42,
            "max_retries": 0,
            "system_prompt": "You are a probe.",
            "output_schema": Out,
        }
        super().__init__(AgentConfig(**{**defaults, **overrides}), llm_client)
        self.parse_output_calls = 0

    def build_prompt(self, evidence: dict[str, Any], context: dict[str, Any]) -> str:
        return f"evidence={sorted(evidence)}"

    def parse_output(self, raw_output: str) -> Out:
        self.parse_output_calls += 1
        return Out.model_validate_json(raw_output)


EVIDENCE = {"manifest": {"package_name": "com.example"}, "permissions": {"count": 1}}


# ---------------------------------------------------------------------------
# The call actually happens
# ---------------------------------------------------------------------------


class TestTheLLMIsCalled:
    async def test_an_agent_with_a_gateway_completes(self) -> None:
        # The regression this whole file is for: this used to raise
        # NotImplementedError and land on AgentStatus.failed.
        agent = ProbeAgent(GatewayDouble('{"verdict": "malicious"}'))

        result = await agent.execute(EVIDENCE, {})

        assert result.status is AgentStatus.completed
        assert result.output.verdict == "malicious"

    async def test_a_missing_client_is_a_configuration_error_naming_the_agent(self) -> None:
        result = await ProbeAgent(llm_client=None).execute(EVIDENCE, {})

        assert result.status is AgentStatus.failed
        assert result.errors[0].error_type == "RuntimeError"
        assert "probe_agent" in result.errors[0].message

    async def test_a_client_with_neither_interface_is_rejected_by_type(self) -> None:
        result = await ProbeAgent(llm_client=object()).execute(EVIDENCE, {})

        assert result.status is AgentStatus.failed
        assert result.errors[0].error_type == "TypeError"


class TestWhatIsForwarded:
    """The agent's own config must reach the provider, not a default."""

    async def test_the_agents_config_is_passed_through_verbatim(self) -> None:
        gateway = GatewayDouble()
        agent = ProbeAgent(gateway)

        await agent.execute(EVIDENCE, {})

        (call,) = gateway.calls
        assert call["model_name"] == "claude-opus-5"
        assert call["temperature"] == 0.25
        assert call["max_tokens"] == 1024
        assert call["timeout_s"] == 42.0
        assert call["system_prompt"] == "You are a probe."

    async def test_the_output_schema_is_passed_so_the_gateway_can_enforce_json(self) -> None:
        # Without this the gateway cannot set JSON mode or run its self-correction
        # turn, and every malformed response costs a full prompt rebuild instead.
        gateway = GatewayDouble()

        await ProbeAgent(gateway).execute(EVIDENCE, {})

        assert gateway.calls[0]["response_schema"] is Out

    async def test_the_built_prompt_is_the_user_turn(self) -> None:
        gateway = GatewayDouble()

        await ProbeAgent(gateway).execute(EVIDENCE, {})

        assert gateway.calls[0]["user_prompt"] == "evidence=['manifest', 'permissions']"


class TestClientShapes:
    async def test_a_complete_only_client_is_driven_through_complete(self) -> None:
        client = ClientDouble()

        result = await ProbeAgent(client).execute(EVIDENCE, {})

        assert result.status is AgentStatus.completed
        assert client.prompts == ["evidence=['manifest', 'permissions']"]

    async def test_an_override_of_call_llm_still_wins(self) -> None:
        """``_call_llm`` is documented as the override point; keep it one."""

        class Overridden(ProbeAgent):
            async def _call_llm(self, prompt: str) -> str:
                return '{"verdict": "from-override"}'

        # No client at all: if the override were bypassed this would fail with the
        # missing-client RuntimeError.
        result = await Overridden(llm_client=None).execute(EVIDENCE, {})

        assert result.output.verdict == "from-override"


# ---------------------------------------------------------------------------
# Token accounting
# ---------------------------------------------------------------------------


class TestTokenAccounting:
    async def test_usage_reported_by_the_provider_is_used_verbatim(self) -> None:
        result = await ProbeAgent(GatewayDouble(tokens=4096)).execute(EVIDENCE, {})

        assert result.tokens_used == 4096

    async def test_a_complete_only_client_reports_its_own_usage(self) -> None:
        result = await ProbeAgent(ClientDouble(tokens=77)).execute(EVIDENCE, {})

        assert result.tokens_used == 77

    async def test_an_override_that_reports_nothing_falls_back_to_the_estimate(self) -> None:
        raw = '{"verdict": "clean"}'

        class Overridden(ProbeAgent):
            async def _call_llm(self, prompt: str) -> str:
                return raw

        agent = Overridden(llm_client=None)
        result = await agent.execute(EVIDENCE, {})

        prompt = agent.build_prompt(EVIDENCE, {})
        assert result.tokens_used == (len(prompt) + len(raw)) // 4

    async def test_usage_from_one_call_does_not_leak_into_the_next(self) -> None:
        """The reading is cleared before each turn, so a stale one cannot be reused."""

        class HalfReporting(ProbeAgent):
            def __init__(self) -> None:
                super().__init__(GatewayDouble(tokens=999))
                self.turns = 0

            async def _call_llm(self, prompt: str) -> str:
                self.turns += 1
                if self.turns == 1:
                    # Report usage the normal way.
                    return await BaseAgent._call_llm(self, prompt)
                # Second turn reports nothing.
                return '{"verdict": "clean"}'

        agent = HalfReporting()
        first = await agent.execute(EVIDENCE, {})
        second = await agent.execute(EVIDENCE, {})

        assert first.tokens_used == 999
        assert second.tokens_used != 999


# ---------------------------------------------------------------------------
# The validation layer is in the path
# ---------------------------------------------------------------------------


class TestValidationIsWired:
    async def test_malformed_json_the_validator_can_repair_survives(self) -> None:
        # Trailing comma and a code fence: json.loads rejects both, JSONRepair does
        # not. Before the validator was wired in, this cost a whole retry.
        agent = ProbeAgent(GatewayDouble('```json\n{"verdict": "clean",}\n```'))

        result = await agent.execute(EVIDENCE, {})

        assert result.status is AgentStatus.completed
        assert result.output.verdict == "clean"
        assert agent.parse_output_calls == 0

    async def test_the_validator_verdict_is_recorded_for_audit(self) -> None:
        result = await ProbeAgent(GatewayDouble()).execute(EVIDENCE, {})

        assert result.metadata["validation"]["status"] in {"valid", "repaired", "partial"}

    async def test_parse_output_remains_the_fallback(self) -> None:
        """Output the validator cannot use still reaches the agent's own parser."""
        agent = ProbeAgent(GatewayDouble("this is not json at all"))

        result = await agent.execute(EVIDENCE, {})

        assert agent.parse_output_calls == 1
        assert result.status is AgentStatus.failed

    async def test_a_confidence_outside_the_unit_interval_is_retried(self) -> None:
        # Structurally valid, semantically impossible. The business rule catches
        # what the schema cannot, and the second turn is given a chance to fix it.
        gateway = GatewayDouble(
            '{"verdict": "clean", "confidence": 4.2}',
            '{"verdict": "clean", "confidence": 0.42}',
        )
        agent = ProbeAgent(gateway, max_retries=1, retry_delay_seconds=0)

        result = await agent.execute(EVIDENCE, {})

        assert len(gateway.calls) == 2
        assert result.status is AgentStatus.completed
        assert result.output.confidence == 0.42

    async def test_an_unfixable_rule_violation_degrades_rather_than_discards(self) -> None:
        # On the last attempt a usable result with a flagged field beats no result,
        # which is the same partial-success policy the engine stages follow.
        agent = ProbeAgent(
            GatewayDouble('{"verdict": "clean", "confidence": 4.2}'),
            max_retries=1,
            retry_delay_seconds=0,
        )

        result = await agent.execute(EVIDENCE, {})

        assert result.status is AgentStatus.partial
        assert result.output is not None
        assert any("confidence" in e for e in result.metadata["validation"]["errors"])


class TestEvidenceGrounding:
    """The check that stops an agent citing analysis that never ran."""

    class Grounded(BaseModel):
        verdict: str
        evidence_references: list[dict[str, Any]] = []

    def _agent(self, raw: str) -> BaseAgent:
        outer = self

        class GroundedAgent(ProbeAgent):
            def __init__(self) -> None:
                super().__init__(GatewayDouble(raw), output_schema=outer.Grounded)

            def parse_output(self, raw_output: str) -> Any:
                self.parse_output_calls += 1
                return outer.Grounded.model_validate_json(raw_output)

        return GroundedAgent()

    async def test_a_reference_to_an_extractor_that_ran_is_accepted_silently(self) -> None:
        agent = self._agent('{"verdict": "x", "evidence_references": [{"extractor": "manifest"}]}')

        result = await agent.execute(EVIDENCE, {})

        assert result.metadata["validation"]["warnings"] == []

    async def test_a_reference_to_an_extractor_that_did_not_run_is_flagged(self) -> None:
        agent = self._agent('{"verdict": "x", "evidence_references": [{"extractor": "invented"}]}')

        result = await agent.execute(EVIDENCE, {})

        # A warning, not a failure: the surrounding analysis may still be sound, and
        # an analyst needs to see the claim *and* that it was unsupported.
        assert result.status is AgentStatus.completed
        warnings = result.metadata["validation"]["warnings"]
        assert any("invented" in w for w in warnings)


# ---------------------------------------------------------------------------
# Retry behaviour around the call
# ---------------------------------------------------------------------------


class TestRetries:
    async def test_a_transient_client_failure_is_retried(self) -> None:
        class FlakyGateway:
            def __init__(self) -> None:
                self.calls = 0

            async def generate(self, **kwargs: Any) -> _GenerateResult:
                self.calls += 1
                if self.calls == 1:
                    raise ConnectionError("provider hung up")
                return _GenerateResult('{"verdict": "clean"}', tokens=10)

        gateway = FlakyGateway()
        agent = ProbeAgent(gateway, max_retries=1, retry_delay_seconds=0)

        result = await agent.execute(EVIDENCE, {})

        assert gateway.calls == 2
        assert result.status is AgentStatus.completed
        # The failed attempt stays visible on the successful result.
        assert [e.error_type for e in result.errors] == ["ConnectionError"]

    async def test_exhausting_the_retries_fails_with_every_attempt_recorded(self) -> None:
        class DeadGateway:
            async def generate(self, **kwargs: Any) -> _GenerateResult:
                raise ConnectionError("provider down")

        agent = ProbeAgent(DeadGateway(), max_retries=2, retry_delay_seconds=0)

        result = await agent.execute(EVIDENCE, {})

        assert result.status is AgentStatus.failed
        assert len(result.errors) == 3
        assert result.output is None


class TestConfigGuards:
    def test_an_agent_without_an_output_schema_is_refused_at_construction(self) -> None:
        with pytest.raises(ValueError, match="output_schema"):
            BaseAgent.__init__(
                object.__new__(ProbeAgent),  # type: ignore[arg-type]
                AgentConfig(name="no_schema"),
            )
