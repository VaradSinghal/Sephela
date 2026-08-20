"""Prove the GenAI stage works against a real provider. ``python -m ai.verify_live``

Why this exists as its own entrypoint rather than a test: no hermetic test can check the
one thing that actually goes wrong here. The provider contract is external — a credential
can be valid and the model slug still 404, a slug can be right and the account out of
credit, and both fail in ways that look identical to a wiring bug from inside the
application.

It runs one agent against one small evidence envelope, which costs a few thousand tokens
rather than the eight-agent full stage. Run it before uploading an APK with
``SEPHELA_AI_ENABLED=true``, because the same failure discovered there costs a whole
pipeline run to observe and reports as a failed stage rather than as a bad credential.

    export OPENROUTER_API_KEY=...        # or ANTHROPIC_API_KEY / OPENAI_API_KEY
    python -m ai.verify_live

Checks, in the order they fail:

1. A provider is registered at all.
2. The selected model slug is one that provider accepts — the mistake this is most likely
   to catch, since a bare ``claude-opus-5`` is correct for Anthropic and a 400 for
   OpenRouter.
3. The model answers, and the answer parses against the agent's schema.
4. Token usage comes back from the provider rather than being estimated.
5. The validation layer ran and said what it thought.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

from ai.agents.manifest import ManifestAgent
from ai.integration import AgentModelConfig
from ai.llm.factory import LLMGateway

#: Small on purpose. A real APK's evidence is tens of kilobytes and this only needs to be
#: enough for the model to have something to say — the permission below is the one a
#: banking-overlay trojan actually needs, so a sane model should flag it.
_EVIDENCE: dict[str, Any] = {
    "manifest": {
        "package_name": "com.example.verify",
        "version_name": "1.0.0",
        "min_sdk": 21,
        "target_sdk": 33,
        "debuggable": True,
    },
    "permissions": {
        "count": 2,
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ],
    },
    "components": {
        "counts": {"activities": 1, "services": 1, "receivers": 0, "providers": 0},
        "activities": ["com.example.verify.MainActivity"],
        "services": ["com.example.verify.A11yService"],
        "receivers": [],
        "providers": [],
        "intent_filters": {},
    },
    "certificate": {"certificates": []},
}


def _line(label: str, value: object) -> None:
    print(f"  {label:.<26} {value}")


async def _run(model_override: str | None) -> int:
    print("Sephela — live GenAI check\n")

    # 1. Providers
    #
    # One attempt, not the gateway's default three. This is a pre-flight check, and a bad
    # credential retried with exponential backoff takes minutes to report what it already
    # knew on the first response — which is exactly the delay this script exists to save.
    try:
        gateway = LLMGateway.from_env(max_retries=1)
    except RuntimeError as exc:
        print(f"FAIL  no provider configured\n      {exc}")
        return 2

    providers = sorted(p.value for p in gateway.providers)
    _line("providers registered", ", ".join(providers))

    # 2. Model selection
    config = AgentModelConfig.for_providers(gateway.providers)
    model = model_override or config.manifest_agent
    _line("model", model)
    try:
        provider = gateway._router.resolve(model)
    except LookupError as exc:
        print(f"\nFAIL  no registered provider can serve {model!r}\n      {exc}")
        return 2
    _line("routes to", provider.provider_name.value)
    if not provider.supports_model(model):
        # Routing fell through to OpenRouter's universal fallback, which forwards the name
        # unchanged. This is the case that produces a 400 the application cannot explain.
        print(
            f"\nWARN  {provider.provider_name.value} does not claim {model!r} — it was\n"
            f"      reached by fallback and will probably reject the request. Try the\n"
            f"      provider-prefixed form, e.g. anthropic/claude-opus-5.\n"
        )

    # 3-5. One real call, through the real agent.
    agent = ManifestAgent(llm_client=gateway)
    agent.config.model = model
    # Same reasoning as the gateway above: no agent-level retries either, and a timeout
    # short enough that an unreachable endpoint reports rather than hangs.
    agent.config.max_retries = 0
    agent.config.timeout_seconds = 60
    print("\n  calling the provider…\n")
    try:
        result = await asyncio.wait_for(agent.execute(_EVIDENCE, {}), timeout=90)
    except TimeoutError:
        print("FAIL  the provider did not answer within 90s.")
        print("      Check network egress to the provider, and that the endpoint is right.")
        return 1

    _line("agent status", result.status.value)
    _line("tokens reported", result.tokens_used)
    estimate = agent._estimate_tokens("", "")
    if result.tokens_used and result.tokens_used != estimate:
        _line("usage source", "provider")
    else:
        _line("usage source", "estimated — the provider reported none")

    validation = result.metadata.get("validation")
    if validation:
        _line("validation", validation.get("status"))
        for issue in validation.get("errors", []) + validation.get("warnings", []):
            _line("  issue", issue)
    else:
        _line("validation", "not run — output fell back to parse_output")

    _line("findings", len(result.findings))
    for finding in result.findings[:5]:
        _line("  finding", f"[{finding.severity}] {finding.title}")

    if result.errors:
        print("\n  errors:")
        for error in result.errors:
            _line(f"  {error.error_type}", error.message[:160])

    if result.status.value == "failed":
        print("\nFAIL  the agent could not produce a usable result.")
        return 1

    await gateway.close()
    print(f"\nOK    the GenAI stage works against {provider.provider_name.value}.")
    if result.status.value == "partial":
        print("      Status is `partial`: the output was usable but the validator flagged")
        print("      something above. That is a model-quality signal, not a wiring fault.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--model",
        help="Override the model. Useful for checking a cheaper slug before a full run.",
    )
    args = parser.parse_args()
    try:
        return asyncio.run(_run(args.model))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
