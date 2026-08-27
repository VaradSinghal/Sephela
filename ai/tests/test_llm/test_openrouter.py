"""Provider adapters — request construction and response parsing.

Driven through ``httpx.MockTransport``, so these cover the wire format each provider
actually requires. The OpenRouter cases carry extra weight: a bare Anthropic model
name reaches OpenRouter as a 400, which is the class of mistake that reads like a
wiring bug and is fixed one layer up in ``AgentModelConfig.for_providers``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from ai.llm.adapters import (
    _ANTHROPIC_BASE,
    _GEMINI_BASE,
    _OPENAI_BASE,
    _OPENROUTER_BASE,
    AnthropicAdapter,
    LocalAdapter,
    OpenAIAdapter,
    OpenRouterAdapter,
)
from ai.llm.provider import ChatCompletionRequest, ChatMessage, ProviderName


def _request(**overrides: Any) -> ChatCompletionRequest:
    base: dict[str, Any] = {
        "model": "anthropic/nvidia/nemotron-3-super-120b-a12b:free",
        "messages": [
            ChatMessage(role="system", content="You are an analyst."),
            ChatMessage(role="user", content="Analyse this."),
        ],
        "temperature": 0.1,
        "max_tokens": 4096,
        "timeout_s": 30.0,
    }
    return ChatCompletionRequest(**{**base, **overrides})


def _ok(body: dict[str, Any]) -> Callable[[httpx.Request], httpx.Response]:
    return lambda _request: httpx.Response(200, json=body)


class TestModelRouting:
    """``supports_model`` is what decides which provider a model name reaches."""

    def test_openrouter_claims_provider_prefixed_slugs(self) -> None:
        assert OpenRouterAdapter(api_key="k").supports_model("anthropic/nvidia/nemotron-3-super-120b-a12b:free") is True

    def test_openrouter_does_not_claim_a_bare_anthropic_name(self) -> None:
        # This is the whole reason AgentModelConfig has to know which providers are
        # registered: OpenRouter needs the prefix and rejects the bare name.
        assert OpenRouterAdapter(api_key="k").supports_model("nvidia/nemotron-3-super-120b-a12b:free") is False

    def test_anthropic_claims_the_claude_family(self) -> None:
        adapter = AnthropicAdapter(api_key="k")

        assert adapter.supports_model("nvidia/nemotron-3-super-120b-a12b:free") is True
        assert adapter.supports_model("claude-haiku-4-5") is True

    def test_anthropic_does_not_claim_the_prefixed_form(self) -> None:
        assert AnthropicAdapter(api_key="k").supports_model("anthropic/nvidia/nemotron-3-super-120b-a12b:free") is False

    def test_openai_claims_its_own_families_only(self) -> None:
        adapter = OpenAIAdapter(api_key="k", provider=ProviderName.OPENAI)

        assert adapter.supports_model("gpt-4o") is True
        assert adapter.supports_model("o1-preview") is True
        assert adapter.supports_model("nvidia/nemotron-3-super-120b-a12b:free") is False

    def test_gemini_claims_gemini_models(self) -> None:
        adapter = OpenAIAdapter(api_key="k", base_url=_GEMINI_BASE, provider=ProviderName.GEMINI)

        assert adapter.supports_model("gemini-1.5-pro") is True
        assert adapter.supports_model("gpt-4o") is False

    def test_local_claims_everything_because_the_server_decides(self) -> None:
        assert LocalAdapter(base_url="http://localhost:11434/v1").supports_model("whatever") is True


class TestOpenRouterRequest:
    async def test_it_posts_to_the_chat_completions_endpoint(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        seen = install_transport(_ok(openai_style_response()))

        await OpenRouterAdapter(api_key="k").complete(_request())

        (request,) = seen
        assert str(request.url) == f"{_OPENROUTER_BASE}/chat/completions"

    async def test_it_sends_the_bearer_token_and_attribution_headers(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        seen = install_transport(_ok(openai_style_response()))

        await OpenRouterAdapter(api_key="secret-key").complete(_request())

        headers = seen[0].headers
        assert headers["authorization"] == "Bearer secret-key"
        # OpenRouter uses these for per-app attribution and rate limiting.
        assert headers["http-referer"]
        assert headers["x-title"]

    async def test_the_model_and_sampling_parameters_are_forwarded(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        seen = install_transport(_ok(openai_style_response()))

        await OpenRouterAdapter(api_key="k").complete(
            _request(model="anthropic/nvidia/nemotron-3-super-120b-a12b:free", temperature=0.7, max_tokens=1000)
        )

        payload = json.loads(seen[0].content)
        assert payload["model"] == "anthropic/nvidia/nemotron-3-super-120b-a12b:free"
        assert payload["temperature"] == 0.7
        assert payload["max_tokens"] == 1000

    async def test_the_system_message_stays_in_the_message_list(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        # OpenAI-shaped APIs take the system turn inline, unlike Anthropic's.
        seen = install_transport(_ok(openai_style_response()))

        await OpenRouterAdapter(api_key="k").complete(_request())

        payload = json.loads(seen[0].content)
        assert payload["messages"][0] == {"role": "system", "content": "You are an analyst."}

    async def test_json_mode_is_requested_when_asked_for(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        # The gateway sets this whenever an agent supplied a schema; without it the
        # model is free to wrap its answer in prose.
        seen = install_transport(_ok(openai_style_response()))

        await OpenRouterAdapter(api_key="k").complete(_request(response_format="json_object"))

        assert json.loads(seen[0].content)["response_format"] == {"type": "json_object"}

    async def test_json_mode_is_omitted_otherwise(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        seen = install_transport(_ok(openai_style_response()))

        await OpenRouterAdapter(api_key="k").complete(_request())

        assert "response_format" not in json.loads(seen[0].content)

    async def test_extra_params_are_merged_into_the_payload(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        seen = install_transport(_ok(openai_style_response()))

        await OpenRouterAdapter(api_key="k").complete(
            _request(extra_params={"provider": {"order": ["Anthropic"]}})
        )

        assert json.loads(seen[0].content)["provider"] == {"order": ["Anthropic"]}


class TestOpenRouterResponse:
    async def test_the_content_usage_and_latency_are_parsed(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        install_transport(
            _ok(
                openai_style_response(
                    content='{"verdict": "malicious"}', prompt_tokens=1200, completion_tokens=340
                )
            )
        )

        response = await OpenRouterAdapter(api_key="k").complete(_request())

        assert response.content == '{"verdict": "malicious"}'
        assert response.provider is ProviderName.OPENROUTER
        assert response.usage.prompt_tokens == 1200
        assert response.usage.completion_tokens == 340
        assert response.usage.total_tokens == 1540
        assert response.latency_ms >= 0

    async def test_a_null_content_becomes_an_empty_string(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        # A filtered or truncated completion returns null here; the gateway's schema
        # validation should report unparseable output, not raise a TypeError.
        body = openai_style_response()
        body["choices"][0]["message"]["content"] = None
        install_transport(_ok(body))

        response = await OpenRouterAdapter(api_key="k").complete(_request())

        assert response.content == ""

    async def test_a_missing_usage_block_defaults_to_zero(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        body = openai_style_response()
        del body["usage"]
        install_transport(_ok(body))

        response = await OpenRouterAdapter(api_key="k").complete(_request())

        assert response.usage.total_tokens == 0

    async def test_the_finish_reason_is_carried(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        # `length` means the answer was cut off, which is why a schema check fails.
        install_transport(_ok(openai_style_response(finish_reason="length")))

        response = await OpenRouterAdapter(api_key="k").complete(_request())

        assert response.finish_reason == "length"

    @pytest.mark.parametrize("status", [400, 401, 402, 429, 500, 503])
    async def test_an_error_status_raises(self, install_transport: Any, status: int) -> None:
        # The gateway's retry loop depends on this raising rather than returning a body.
        install_transport(lambda _r: httpx.Response(status, json={"error": {"message": "no"}}))

        with pytest.raises(httpx.HTTPStatusError):
            await OpenRouterAdapter(api_key="k").complete(_request())


class TestAnthropicAdapter:
    async def test_it_posts_to_the_messages_endpoint_with_the_version_header(
        self, install_transport: Any, anthropic_style_response: Any
    ) -> None:
        seen = install_transport(_ok(anthropic_style_response()))

        await AnthropicAdapter(api_key="k").complete(_request(model="nvidia/nemotron-3-super-120b-a12b:free"))

        request = seen[0]
        assert str(request.url) == f"{_ANTHROPIC_BASE}/v1/messages"
        assert request.headers["anthropic-version"]
        assert request.headers["x-api-key"] == "k"

    async def test_the_system_turn_is_hoisted_out_of_the_message_list(
        self, install_transport: Any, anthropic_style_response: Any
    ) -> None:
        # The Messages API takes `system` as a top-level field and rejects a system
        # role inside `messages`.
        seen = install_transport(_ok(anthropic_style_response()))

        await AnthropicAdapter(api_key="k").complete(_request(model="nvidia/nemotron-3-super-120b-a12b:free"))

        payload = json.loads(seen[0].content)
        assert payload["system"] == "You are an analyst."
        assert [m["role"] for m in payload["messages"]] == ["user"]

    async def test_a_system_only_request_still_carries_a_user_turn(
        self, install_transport: Any, anthropic_style_response: Any
    ) -> None:
        # The API requires at least one user message, so an empty list is a 400.
        seen = install_transport(_ok(anthropic_style_response()))

        await AnthropicAdapter(api_key="k").complete(
            _request(model="nvidia/nemotron-3-super-120b-a12b:free", messages=[ChatMessage(role="system", content="S")])
        )

        payload = json.loads(seen[0].content)
        assert payload["messages"] == [{"role": "user", "content": "Proceed."}]

    async def test_text_blocks_are_concatenated(
        self, install_transport: Any, anthropic_style_response: Any
    ) -> None:
        body = anthropic_style_response()
        body["content"] = [
            {"type": "text", "text": '{"a":'},
            {"type": "text", "text": " 1}"},
        ]
        install_transport(_ok(body))

        response = await AnthropicAdapter(api_key="k").complete(_request(model="nvidia/nemotron-3-super-120b-a12b:free"))

        assert response.content == '{"a": 1}'

    async def test_non_text_blocks_are_ignored(
        self, install_transport: Any, anthropic_style_response: Any
    ) -> None:
        body = anthropic_style_response(content='{"ok": true}')
        body["content"].insert(0, {"type": "thinking", "thinking": "hmm"})
        install_transport(_ok(body))

        response = await AnthropicAdapter(api_key="k").complete(_request(model="nvidia/nemotron-3-super-120b-a12b:free"))

        assert response.content == '{"ok": true}'

    async def test_anthropic_usage_field_names_are_mapped(
        self, install_transport: Any, anthropic_style_response: Any
    ) -> None:
        # input_tokens/output_tokens here, prompt/completion everywhere else.
        install_transport(_ok(anthropic_style_response(input_tokens=900, output_tokens=120)))

        response = await AnthropicAdapter(api_key="k").complete(_request(model="nvidia/nemotron-3-super-120b-a12b:free"))

        assert response.usage.prompt_tokens == 900
        assert response.usage.completion_tokens == 120


class TestOpenAIAdapter:
    async def test_it_posts_to_the_configured_base_url(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        seen = install_transport(_ok(openai_style_response(model="gpt-4o")))

        await OpenAIAdapter(api_key="k", provider=ProviderName.OPENAI).complete(
            _request(model="gpt-4o")
        )

        assert str(seen[0].url) == f"{_OPENAI_BASE}/chat/completions"

    async def test_gemini_goes_to_its_compatibility_endpoint(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        seen = install_transport(_ok(openai_style_response(model="gemini-1.5-pro")))

        await OpenAIAdapter(
            api_key="k", base_url=_GEMINI_BASE, provider=ProviderName.GEMINI
        ).complete(_request(model="gemini-1.5-pro"))

        assert str(seen[0].url).startswith(_GEMINI_BASE)

    async def test_the_provider_is_reported_as_configured(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        # Both OpenAI and Gemini use this adapter, so the response must say which.
        install_transport(_ok(openai_style_response()))

        response = await OpenAIAdapter(
            api_key="k", base_url=_GEMINI_BASE, provider=ProviderName.GEMINI
        ).complete(_request(model="gemini-1.5-pro"))

        assert response.provider is ProviderName.GEMINI


class TestLocalAdapter:
    async def test_a_trailing_slash_in_the_base_url_is_normalised(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        seen = install_transport(_ok(openai_style_response(model="llama3")))

        await LocalAdapter(base_url="http://localhost:11434/v1/").complete(_request(model="llama3"))

        assert "//chat" not in str(seen[0].url)

    async def test_it_reports_itself_as_the_local_provider(
        self, install_transport: Any, openai_style_response: Any
    ) -> None:
        install_transport(_ok(openai_style_response(model="llama3")))

        response = await LocalAdapter(base_url="http://localhost:11434/v1").complete(
            _request(model="llama3")
        )

        assert response.provider is ProviderName.LOCAL
