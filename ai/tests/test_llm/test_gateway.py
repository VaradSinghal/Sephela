"""LLMGateway and ModelRouter — routing, retries, and schema self-correction.

The routing tests are the important ones. Resolution has four steps and the last is a
fallback that hands an unrecognised model to OpenRouter regardless of how it is
spelled — which is how a bare ``claude-opus-5`` reached OpenRouter's API and 400'd on
every agent call.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, Field

from ai.integration import AgentModelConfig
from ai.llm.adapters import AnthropicAdapter, OpenAIAdapter, OpenRouterAdapter
from ai.llm.factory import LLMGateway, ModelRouter
from ai.llm.provider import (
    BaseLLMProvider,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ProviderName,
    TokenUsage,
)


class Verdict(BaseModel):
    verdict: str
    score: float = Field(0.0, ge=0.0, le=100.0)


class FakeProvider(BaseLLMProvider):
    """A provider that answers from a scripted list and records what it was asked."""

    def __init__(
        self,
        name: ProviderName,
        *responses: str,
        supports: tuple[str, ...] = (),
        fail_times: int = 0,
    ) -> None:
        self._name = name
        self._responses = list(responses) or ['{"verdict": "clean"}']
        self._supports = supports
        self._fail_times = fail_times
        self.requests: list[ChatCompletionRequest] = []
        self.closed = False

    @property
    def provider_name(self) -> ProviderName:
        return self._name

    def supports_model(self, model_id: str) -> bool:
        return any(model_id.startswith(p) for p in self._supports)

    async def complete(self, request: ChatCompletionRequest) -> ChatCompletionResponse:
        self.requests.append(request)
        if len(self.requests) <= self._fail_times:
            raise ConnectionError("provider unavailable")
        content = self._responses[min(len(self.requests) - 1, len(self._responses) - 1)]
        return ChatCompletionResponse(
            content=content,
            model=request.model,
            provider=self._name,
            usage=TokenUsage(prompt_tokens=10, completion_tokens=5),
            latency_ms=1,
            finish_reason="stop",
            raw={},
        )

    async def close(self) -> None:
        self.closed = True


def _gateway(*providers: BaseLLMProvider, max_retries: int = 3) -> LLMGateway:
    gw = LLMGateway(providers=list(providers), max_retries=max_retries)
    # Retries would otherwise sleep 2s, 4s, 8s.
    gw._base_retry_delay = 0.0
    return gw


async def _generate(gateway: LLMGateway, model: str = "claude-opus-5", **kwargs: Any):
    return await gateway.generate(model_name=model, system_prompt="S", user_prompt="U", **kwargs)


class TestRouting:
    def test_a_provider_that_claims_the_model_wins(self) -> None:
        anthropic = FakeProvider(ProviderName.ANTHROPIC, supports=("claude",))
        openrouter = FakeProvider(ProviderName.OPENROUTER, supports=())
        router = ModelRouter([anthropic, openrouter])

        assert router.resolve("claude-opus-5") is anthropic

    def test_the_prefix_map_resolves_a_model_nobody_claims(self) -> None:
        # OpenAI's adapter claims gpt-, but suppose a registered provider does not:
        # the prefix table still routes gpt-4o to whichever provider is OPENAI.
        openai = FakeProvider(ProviderName.OPENAI, supports=())
        router = ModelRouter([openai])

        assert router.resolve("gpt-4o") is openai

    def test_openrouter_is_the_last_resort_for_an_unknown_model(self) -> None:
        openrouter = FakeProvider(ProviderName.OPENROUTER, supports=())
        router = ModelRouter([openrouter])

        assert router.resolve("some-model-nobody-knows") is openrouter

    def test_a_bare_anthropic_name_still_lands_on_openrouter(self) -> None:
        # Documenting the trap rather than endorsing it: routing succeeds and the
        # *request* then fails at the provider, because OpenRouter needs the
        # `anthropic/` prefix. AgentModelConfig.for_providers is what prevents it.
        openrouter = FakeProvider(ProviderName.OPENROUTER, supports=())
        router = ModelRouter([openrouter])

        assert router.resolve("claude-opus-5").provider_name is ProviderName.OPENROUTER

    def test_an_unroutable_model_raises_and_names_what_is_registered(self) -> None:
        router = ModelRouter([FakeProvider(ProviderName.OPENAI, supports=("gpt-",))])

        with pytest.raises(LookupError, match="openai"):
            router.resolve("claude-opus-5")

    def test_the_registered_providers_are_reported(self) -> None:
        router = ModelRouter(
            [FakeProvider(ProviderName.ANTHROPIC), FakeProvider(ProviderName.OPENROUTER)]
        )

        assert router.providers == frozenset({ProviderName.ANTHROPIC, ProviderName.OPENROUTER})

    def test_the_gateway_exposes_them_too(self) -> None:
        gateway = _gateway(FakeProvider(ProviderName.OPENROUTER))

        assert gateway.providers == frozenset({ProviderName.OPENROUTER})


class TestGenerate:
    async def test_the_prompts_become_a_system_and_a_user_turn(self) -> None:
        provider = FakeProvider(ProviderName.ANTHROPIC, supports=("claude",))

        await _generate(_gateway(provider))

        (request,) = provider.requests
        assert [(m.role, m.content) for m in request.messages] == [
            ("system", "S"),
            ("user", "U"),
        ]

    async def test_the_result_carries_content_usage_and_provider(self) -> None:
        provider = FakeProvider(
            ProviderName.ANTHROPIC, '{"verdict": "malicious"}', supports=("claude",)
        )

        result = await _generate(_gateway(provider))

        assert result.content == '{"verdict": "malicious"}'
        assert result.provider is ProviderName.ANTHROPIC
        assert result.usage.total_tokens == 15
        assert result.attempts == 1

    async def test_without_a_schema_nothing_is_parsed(self) -> None:
        provider = FakeProvider(ProviderName.ANTHROPIC, "free prose", supports=("claude",))

        result = await _generate(_gateway(provider))

        assert result.parsed is None

    async def test_json_mode_is_requested_only_when_a_schema_is_given(self) -> None:
        provider = FakeProvider(ProviderName.ANTHROPIC, supports=("claude",))
        gateway = _gateway(provider)

        await _generate(gateway)
        await _generate(gateway, response_schema=Verdict)

        assert provider.requests[0].response_format is None
        assert provider.requests[1].response_format == "json_object"


class TestSchemaValidation:
    async def test_valid_json_is_parsed_into_the_schema(self) -> None:
        provider = FakeProvider(
            ProviderName.ANTHROPIC, '{"verdict": "clean", "score": 3}', supports=("claude",)
        )

        result = await _generate(_gateway(provider), response_schema=Verdict)

        assert isinstance(result.parsed, Verdict)
        assert result.parsed.score == 3.0
        assert len(provider.requests) == 1

    async def test_json_inside_a_code_fence_is_extracted(self) -> None:
        provider = FakeProvider(
            ProviderName.ANTHROPIC,
            '```json\n{"verdict": "clean"}\n```',
            supports=("claude",),
        )

        result = await _generate(_gateway(provider), response_schema=Verdict)

        assert result.parsed is not None
        assert len(provider.requests) == 1

    async def test_a_schema_miss_triggers_one_self_correction_turn(self) -> None:
        provider = FakeProvider(
            ProviderName.ANTHROPIC,
            "I think it is probably clean.",
            '{"verdict": "clean"}',
            supports=("claude",),
        )

        result = await _generate(_gateway(provider), response_schema=Verdict)

        assert result.parsed is not None
        assert len(provider.requests) == 2

    async def test_the_correction_turn_shows_the_model_its_own_output(self) -> None:
        provider = FakeProvider(
            ProviderName.ANTHROPIC, "not json", '{"verdict": "clean"}', supports=("claude",)
        )

        await _generate(_gateway(provider), response_schema=Verdict)

        correction = provider.requests[1]
        roles = [m.role for m in correction.messages]
        assert roles[-2:] == ["assistant", "user"]
        assert "not json" in correction.messages[-2].content
        # The schema itself is restated so the model has something to conform to.
        assert "verdict" in correction.messages[-1].content

    async def test_the_correction_turn_is_deterministic(self) -> None:
        # Sampling is what produced the malformed answer; retrying at the same
        # temperature just rolls the dice again.
        provider = FakeProvider(
            ProviderName.ANTHROPIC, "not json", '{"verdict": "clean"}', supports=("claude",)
        )

        await _generate(_gateway(provider), response_schema=Verdict, temperature=0.9)

        assert provider.requests[1].temperature == 0.0

    async def test_a_correction_that_also_fails_leaves_parsed_unset(self) -> None:
        # The raw content still comes back, so the caller can fall back to its own
        # parser rather than losing the turn entirely.
        provider = FakeProvider(
            ProviderName.ANTHROPIC, "not json", "still not json", supports=("claude",)
        )

        result = await _generate(_gateway(provider), response_schema=Verdict)

        assert result.parsed is None
        assert result.content == "still not json"

    async def test_output_violating_a_field_bound_is_treated_as_a_miss(self) -> None:
        provider = FakeProvider(
            ProviderName.ANTHROPIC,
            '{"verdict": "clean", "score": 9001}',
            '{"verdict": "clean", "score": 90}',
            supports=("claude",),
        )

        result = await _generate(_gateway(provider), response_schema=Verdict)

        assert result.parsed is not None
        assert result.parsed.score == 90.0


class TestRetries:
    async def test_a_transient_failure_is_retried(self) -> None:
        provider = FakeProvider(ProviderName.ANTHROPIC, supports=("claude",), fail_times=1)

        result = await _generate(_gateway(provider))

        assert len(provider.requests) == 2
        assert result.attempts == 2

    async def test_exhausting_the_retries_raises_with_the_model_named(self) -> None:
        provider = FakeProvider(ProviderName.ANTHROPIC, supports=("claude",), fail_times=99)

        with pytest.raises(RuntimeError, match="claude-opus-5"):
            await _generate(_gateway(provider, max_retries=2))

        assert len(provider.requests) == 2


class TestLifecycle:
    async def test_closing_the_gateway_closes_every_provider(self) -> None:
        anthropic = FakeProvider(ProviderName.ANTHROPIC, supports=("claude",))
        openrouter = FakeProvider(ProviderName.OPENROUTER)
        gateway = _gateway(anthropic, openrouter)

        await gateway.close()

        assert anthropic.closed and openrouter.closed


class TestModelConfigSelection:
    """``AgentModelConfig`` must name models the registered providers can serve."""

    def test_openrouter_alone_selects_prefixed_slugs(self) -> None:
        config = AgentModelConfig.for_providers([ProviderName.OPENROUTER])

        assert config.manifest_agent == "anthropic/claude-opus-5"
        assert config.report_agent == "anthropic/claude-opus-5"

    def test_anthropic_selects_the_bare_name(self) -> None:
        config = AgentModelConfig.for_providers([ProviderName.ANTHROPIC])

        assert config.manifest_agent == "claude-opus-5"

    def test_anthropic_wins_when_both_are_registered(self) -> None:
        # The prompts were written against Claude, and the first-party API is the
        # shorter path to it.
        config = AgentModelConfig.for_providers([ProviderName.OPENROUTER, ProviderName.ANTHROPIC])

        assert config.manifest_agent == "claude-opus-5"

    def test_openai_alone_selects_an_openai_model(self) -> None:
        # Not claude-opus-5: with no Anthropic and no OpenRouter registered, that name
        # resolves to nothing and every agent raises LookupError.
        config = AgentModelConfig.for_providers([ProviderName.OPENAI])

        assert config.manifest_agent == "gpt-4o"

    def test_gemini_alone_selects_a_gemini_model(self) -> None:
        config = AgentModelConfig.for_providers([ProviderName.GEMINI])

        assert config.manifest_agent == "gemini-1.5-pro"

    def test_no_providers_falls_back_to_the_documented_default(self) -> None:
        assert AgentModelConfig.for_providers([]).manifest_agent == "claude-opus-5"

    def test_every_agent_gets_a_model(self) -> None:
        config = AgentModelConfig.for_providers([ProviderName.OPENROUTER])

        for field_name in AgentModelConfig.__dataclass_fields__:
            assert getattr(config, field_name), f"{field_name} has no model"

    def test_a_per_agent_env_override_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CODE_MODEL", "deepseek/deepseek-coder")

        config = AgentModelConfig.for_providers([ProviderName.OPENROUTER])

        assert config.code_agent == "deepseek/deepseek-coder"
        # Only the one that was overridden moves.
        assert config.manifest_agent == "anthropic/claude-opus-5"

    def test_the_openrouter_preset_matches_provider_selection(self) -> None:
        # One source of truth for the slugs, so the preset cannot drift from the
        # inference path.
        assert AgentModelConfig.openrouter_defaults() == AgentModelConfig.for_providers(
            [ProviderName.OPENROUTER]
        )

    @pytest.mark.parametrize(
        ("provider_name", "adapter"),
        [
            (ProviderName.OPENROUTER, OpenRouterAdapter(api_key="k")),
            (ProviderName.ANTHROPIC, AnthropicAdapter(api_key="k")),
            (ProviderName.OPENAI, OpenAIAdapter(api_key="k", provider=ProviderName.OPENAI)),
        ],
    )
    def test_the_selected_model_is_one_the_real_adapter_accepts(
        self, provider_name: ProviderName, adapter: BaseLLMProvider
    ) -> None:
        # The point of all of the above, checked against the real supports_model rather
        # than a fake: every agent's selected model must be a name that adapter claims.
        config = AgentModelConfig.for_providers([provider_name])

        for field_name in AgentModelConfig.__dataclass_fields__:
            model = getattr(config, field_name)
            assert adapter.supports_model(model) is True, f"{provider_name}: {model}"

    def test_the_selected_model_routes_to_the_registered_adapter(self) -> None:
        adapter = OpenRouterAdapter(api_key="k")
        router = ModelRouter([adapter])
        config = AgentModelConfig.for_providers([ProviderName.OPENROUTER])

        assert router.resolve(config.manifest_agent) is adapter
