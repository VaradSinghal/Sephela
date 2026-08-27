"""
ai/integration.py — Complete integration layer wiring the full AI subsystem.

This module shows exactly how every component connects:

    LangGraph (workflow.py)
        ↓ graph node calls
    Agent (e.g., ManifestAgent.analyze)
        ↓ builds prompt via PromptManager
    LLMGateway.generate(model, system, user, schema)
        ↓ routes to AnthropicAdapter / OpenRouterAdapter / etc.
    Provider HTTP call → raw LLM response
        ↓ JSON extraction + schema validation
    ResponseValidator.validate(raw_text, evidence)
        ↓ JSONRepair → SchemaValidator → business rules
    ManifestAnalysisResult (Pydantic model)
        ↓ serialised to dict
    GraphState.agent_results["manifest_agent"] = result_dict
        ↓ downstream agents read it
    RiskAgent consumes all 6 agent results
        ↓ computes RiskAssessmentResult
    GraphState.risk_result = risk_dict
        ↓
    ReportAgent produces ReportResult
        ↓
    GraphState.report = report_dict  →  pipeline complete

Public API
----------
    # Simplest possible usage:
    from ai.integration import SephelaAnalysisPipeline

    pipeline = SephelaAnalysisPipeline.from_env()
    result = await pipeline.analyze(
        apk_sha256="abc123...",
        evidence_envelope=extracted_evidence_dict,
    )
    print(result.report["executive_summary"]["verdict"])
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from ai.llm.factory import LLMGateway
from ai.llm.provider import ProviderName
from ai.orchestration.workflow import WorkflowConfig, build_workflow

_LOG = logging.getLogger("sephela.integration")


# ---------------------------------------------------------------------------
# AgentConfig — per-agent LLM model assignment
# ---------------------------------------------------------------------------


#: The model every agent uses when nothing more specific is configured, per
#: provider. Which slug is correct is not a preference — the *same* model is
#: ``nvidia/nemotron-3-super-120b-a12b:free`` to Anthropic's API and ``anthropic/nvidia/nemotron-3-super-120b-a12b:free`` to
#: OpenRouter's, and each rejects the other's spelling. So the default cannot be a
#: single constant; it has to be chosen from what is actually registered.
_PROVIDER_DEFAULT_MODEL: dict[ProviderName, str] = {
    ProviderName.ANTHROPIC: "nvidia/nemotron-3-super-120b-a12b:free",
    ProviderName.OPENROUTER: "nvidia/nemotron-3-super-120b-a12b:free",
    ProviderName.OPENAI: "gpt-4o",
    ProviderName.GEMINI: "gemini-1.5-pro",
    ProviderName.LOCAL: "local/default",
}

#: Preference order when several providers are registered. Anthropic first because
#: the prompts and schemas in ai/prompts/ were written and tuned against Claude;
#: OpenRouter second because it can serve the same model, just more indirectly.
_PROVIDER_PREFERENCE: tuple[ProviderName, ...] = (
    ProviderName.OPENROUTER,
    ProviderName.ANTHROPIC,
    ProviderName.OPENAI,
    ProviderName.GEMINI,
    ProviderName.LOCAL,
)

#: Per-agent environment override. Set ``CODE_MODEL=deepseek/deepseek-coder`` to
#: move one agent without touching the rest.
_AGENT_MODEL_ENV_VARS: dict[str, str] = {
    "manifest_agent": "MANIFEST_MODEL",
    "permission_agent": "PERMISSION_MODEL",
    "code_agent": "CODE_MODEL",
    "api_agent": "API_MODEL",
    "network_agent": "NETWORK_MODEL",
    "threat_intel_agent": "THREAT_INTEL_MODEL",
    "risk_agent": "RISK_MODEL",
    "report_agent": "REPORT_MODEL",
}


@dataclass
class AgentModelConfig:
    """
    Maps each agent to its preferred model.

    Agents are independent; different agents can use different models,
    e.g. code agents may prefer DeepSeek-Coder.

    Prefer ``for_providers(gateway.providers)`` over constructing this directly:
    the field defaults below spell the model the Anthropic way, which an
    OpenRouter-only deployment cannot serve.
    """

    manifest_agent: str = field(
        default_factory=lambda: os.getenv("MANIFEST_MODEL", "nvidia/nemotron-3-super-120b-a12b:free")
    )
    permission_agent: str = field(
        default_factory=lambda: os.getenv("PERMISSION_MODEL", "nvidia/nemotron-3-super-120b-a12b:free")
    )
    code_agent: str = field(default_factory=lambda: os.getenv("CODE_MODEL", "nvidia/nemotron-3-super-120b-a12b:free"))
    api_agent: str = field(default_factory=lambda: os.getenv("API_MODEL", "nvidia/nemotron-3-super-120b-a12b:free"))
    network_agent: str = field(default_factory=lambda: os.getenv("NETWORK_MODEL", "nvidia/nemotron-3-super-120b-a12b:free"))
    threat_intel_agent: str = field(
        default_factory=lambda: os.getenv("THREAT_INTEL_MODEL", "nvidia/nemotron-3-super-120b-a12b:free")
    )
    risk_agent: str = field(default_factory=lambda: os.getenv("RISK_MODEL", "nvidia/nemotron-3-super-120b-a12b:free"))
    report_agent: str = field(default_factory=lambda: os.getenv("REPORT_MODEL", "nvidia/nemotron-3-super-120b-a12b:free"))

    @classmethod
    def for_providers(cls, providers: Iterable[ProviderName]) -> AgentModelConfig:
        """Defaults the registered providers can actually serve.

        Without this, an OpenRouter-only deployment fails on every agent call. The
        bare ``nvidia/nemotron-3-super-120b-a12b:free`` default finds no explicit supporter, so
        ``ModelRouter.resolve`` falls through to its OpenRouter-as-universal-fallback
        branch and forwards the Anthropic spelling to an API that requires
        ``anthropic/nvidia/nemotron-3-super-120b-a12b:free`` — a 400 on every request that reads like a wiring
        bug rather than a naming one.

        Per-agent ``*_MODEL`` environment variables still win, so a deliberate
        choice is never overridden by this inference.
        """
        registered = frozenset(providers)
        fallback = next(
            (_PROVIDER_DEFAULT_MODEL[name] for name in _PROVIDER_PREFERENCE if name in registered),
            _PROVIDER_DEFAULT_MODEL[ProviderName.OPENROUTER],
        )
        return cls(
            **{
                agent: os.getenv(env_var) or fallback
                for agent, env_var in _AGENT_MODEL_ENV_VARS.items()
            }
        )

    @classmethod
    def openrouter_defaults(cls) -> AgentModelConfig:
        """Route every agent through OpenRouter instead of a first-party API.

        OpenRouter's catalogue lags first-party releases, so verify the slug at
        https://openrouter.ai/models before relying on this preset.
        """
        return cls.for_providers([ProviderName.OPENROUTER])

    @classmethod
    def fast_cheap(cls) -> AgentModelConfig:
        """Triage preset: cheap model for extraction, best model for judgement.

        The six analysis agents mostly restate structure they were handed, which a
        small model does acceptably. Risk and report are where the actual reasoning
        happens — downgrading those changes the verdict, so they stay on Opus.
        """
        return cls(
            manifest_agent="claude-haiku-4-5",
            permission_agent="claude-haiku-4-5",
            code_agent="claude-haiku-4-5",
            api_agent="claude-haiku-4-5",
            network_agent="claude-haiku-4-5",
            threat_intel_agent="claude-haiku-4-5",
            risk_agent="nvidia/nemotron-3-super-120b-a12b:free",
            report_agent="nvidia/nemotron-3-super-120b-a12b:free",
        )


# ---------------------------------------------------------------------------
# Pipeline result
# ---------------------------------------------------------------------------


@dataclass
class PipelineResult:
    """Final output of a complete analysis pipeline run."""

    job_id: str
    apk_sha256: str
    status: str  # "completed" | "partial" | "failed"
    report: dict[str, Any]  # ReportResult serialised
    risk_result: dict[str, Any]  # RiskAssessmentResult serialised
    agent_results: dict[str, Any]  # All 6 analysis agent results
    graph_state: dict[str, Any]  # Raw final GraphState for debugging
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Main pipeline class
# ---------------------------------------------------------------------------


class SephelaAnalysisPipeline:
    """
    High-level pipeline that wires LangGraph, agents, LLM layer,
    validation, and schemas into a single callable.

    The internal wiring::

        build_workflow(WorkflowConfig)
            → CompiledStateGraph (LangGraph)

        Per-node execution (inside orchestrator.py make_agent_node):
            1. Agent receives GraphState slice
            2. Agent calls PromptManager to build system + user prompts
            3. Agent calls LLMGateway.generate(model, system, user, schema)
            4. Gateway routes to provider, gets raw response
            5. Gateway extracts JSON, runs self-correction if needed
            6. Agent calls ResponseValidator.validate(raw_text, evidence)
            7. Validator runs JSONRepair → SchemaValidator → business rules
            8. Agent stores validated Pydantic model in agent_results dict
            9. GraphState reducer merges results from parallel branches

        After all 6 analysis agents complete:
            10. RiskAgent reads all 6 results from agent_results
            11. Computes RiskAssessmentResult, stored in risk_result
            12. ReportAgent reads risk_result + all agent_results
            13. Produces ReportResult, stored in report
    """

    def __init__(
        self,
        gateway: LLMGateway,
        model_config: AgentModelConfig | None = None,
        analysis_timeout_s: float = 600.0,
        risk_timeout_s: float = 600.0,
        report_timeout_s: float = 600.0,
        max_retries: int = 2,
        checkpointer: Any = None,
        knowledge: Any = None,
    ) -> None:
        self._gateway = gateway
        # Not `or AgentModelConfig()`: the bare defaults name Anthropic-spelled
        # models, which an OpenRouter-only gateway cannot route.
        self._model_config = model_config or AgentModelConfig.for_providers(gateway.providers)
        self._analysis_timeout_s = analysis_timeout_s
        self._risk_timeout_s = risk_timeout_s
        self._report_timeout_s = report_timeout_s
        self._max_retries = max_retries
        self._checkpointer = checkpointer
        self._knowledge = knowledge

        # Build and compile the LangGraph workflow
        workflow_cfg = WorkflowConfig(
            llm_client=gateway,
            analysis_timeout_s=analysis_timeout_s,
            max_retries=max_retries,
            checkpointer=checkpointer,
            agent_overrides=self._build_agent_overrides(),
            knowledge=knowledge,
        )
        self._compiled_graph = build_workflow(workflow_cfg)
        _LOG.info("SephelaAnalysisPipeline initialised. Graph compiled successfully.")

    # ------------------------------------------------------------------
    # Factory constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_env(
        cls,
        model_config: AgentModelConfig | None = None,
        **kwargs: Any,
    ) -> SephelaAnalysisPipeline:
        """
        Construct from environment variables.

        Reads ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, etc.
        """
        gateway = LLMGateway.from_env()
        return cls(gateway=gateway, model_config=model_config, **kwargs)

    @classmethod
    def from_gateway(
        cls,
        gateway: LLMGateway,
        model_config: AgentModelConfig | None = None,
        **kwargs: Any,
    ) -> SephelaAnalysisPipeline:
        """Construct from a pre-built LLMGateway."""
        return cls(gateway=gateway, model_config=model_config, **kwargs)

    @classmethod
    async def build_with_rag(
        cls,
        model_config: AgentModelConfig | None = None,
        **kwargs: Any,
    ) -> SephelaAnalysisPipeline:
        """
        Construct a pipeline with the full RAG knowledge service attached.
        This parses the bundled corpus offline.
        """
        from ai.rag.service import build_knowledge_service

        knowledge = await build_knowledge_service()
        gateway = LLMGateway.from_env()
        return cls(gateway=gateway, model_config=model_config, knowledge=knowledge, **kwargs)

    # ------------------------------------------------------------------
    # Primary API
    # ------------------------------------------------------------------

    async def analyze(
        self,
        apk_sha256: str,
        evidence_envelope: dict[str, Any],
        job_id: str | None = None,
    ) -> PipelineResult:
        """
        Run the complete multi-agent analysis pipeline.

        Args:
            apk_sha256:        SHA-256 hash of the APK being analysed.
            evidence_envelope: Dict of extractor outputs (manifest, code_intel,
                               network_indicators, threat_intel, etc.)
            job_id:            Optional job identifier. Auto-generated if None.

        Returns:
            PipelineResult with report, risk_result, and all agent outputs.
        """
        import uuid

        if job_id is None:
            job_id = uuid.uuid4().hex

        from ai.orchestration.graph_state import initial_state

        # Build initial graph state
        initial = initial_state(
            job_id=job_id,
            apk_sha256=apk_sha256,
            evidence=evidence_envelope,
        )

        _LOG.info(
            '{"event":"pipeline_start","job_id":"%s","sha256":"%s"}',
            job_id,
            apk_sha256[:16],
        )

        try:
            # Run the compiled LangGraph
            final_state = await self._compiled_graph.ainvoke(
                initial,
                config={"recursion_limit": 50},
            )
        except Exception as exc:
            _LOG.error('{"event":"pipeline_error","job_id":"%s","error":"%s"}', job_id, exc)
            return PipelineResult(
                job_id=job_id,
                apk_sha256=apk_sha256,
                status="failed",
                report={},
                risk_result={},
                agent_results={},
                graph_state={},
                errors=[str(exc)],
            )

        # Extract results from final state
        agent_results = final_state.get("agent_results", {})
        risk_result = final_state.get("risk_result", {})
        report = final_state.get("report", {})
        errors = final_state.get("errors", [])

        status = "completed"
        if errors:
            status = "partial"
        if not report:
            status = "failed"

        _LOG.info(
            '{"event":"pipeline_complete","job_id":"%s","status":"%s","agents_completed":%d}',
            job_id,
            status,
            len(agent_results),
        )

        return PipelineResult(
            job_id=job_id,
            apk_sha256=apk_sha256,
            status=status,
            report=report,
            risk_result=risk_result,
            agent_results=agent_results,
            graph_state=dict(final_state),
            errors=errors,
        )

    def get_mermaid_diagram(self) -> str:
        """Return this pipeline's compiled graph as a Mermaid diagram string.

        Drawn from the graph this instance already built rather than via
        ``workflow.get_mermaid_diagram()``, which takes a WorkflowConfig and would
        compile a second, differently-configured graph.
        """
        try:
            return self._compiled_graph.get_graph().draw_mermaid()
        except Exception:  # noqa: BLE001
            from ai.orchestration.workflow import get_mermaid_diagram

            return get_mermaid_diagram()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_agent_overrides(self) -> dict[str, dict[str, Any]]:
        """Build per-agent config overrides from AgentModelConfig."""
        mc = self._model_config
        return {
            "manifest_agent": {"model": mc.manifest_agent},
            "permission_agent": {"model": mc.permission_agent},
            "code_agent": {"model": mc.code_agent},
            "api_agent": {"model": mc.api_agent},
            "network_agent": {"model": mc.network_agent},
            "threat_intel_agent": {"model": mc.threat_intel_agent},
            "risk_agent": {"model": mc.risk_agent},
            "report_agent": {"model": mc.report_agent},
        }


# ---------------------------------------------------------------------------
# Integration wiring diagram (documentation only)
# ---------------------------------------------------------------------------

INTEGRATION_WIRING = """
╔══════════════════════════════════════════════════════════════════════════╗
║                  SEPHELA AI SUBSYSTEM — INTEGRATION MAP                  ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  Evidence Envelope (APK extractor outputs)                               ║
║           │                                                              ║
║           ▼                                                              ║
║  GraphState.initial_state(job_id, sha256, evidence)                      ║
║           │                                                              ║
║           ▼                                                              ║
║  ┌─────────────────────────────────────────────────────────┐             ║
║  │            LangGraph CompiledStateGraph                  │             ║
║  │                                                          │             ║
║  │  orchestrator_start → check_evidence → fanout_gate       │             ║
║  │                              │                          │             ║
║  │         ┌────────────────────┼────────────────────┐     │             ║
║  │         ▼         ▼          ▼         ▼          ▼     │             ║
║  │   manifest  permission   code_agent  api_agent  network │             ║
║  │   _agent    _agent       (parallel)  (parallel) _agent  │             ║
║  │                              │                          │             ║
║  │                    threat_intel_agent                    │             ║
║  │                         │                              │             ║
║  │                  analysis_join (barrier)                │             ║
║  │                         │                              │             ║
║  │                    risk_agent                           │             ║
║  │                         │                              │             ║
║  │                   report_agent                          │             ║
║  │                         │                              │             ║
║  │                      finalise                           │             ║
║  └─────────────────────────────────────────────────────────┘             ║
║           │                                                              ║
║           ▼                                                              ║
║  Per-agent execution (inside orchestrator.py make_agent_node):           ║
║                                                                          ║
║  Agent.analyze(state)                                                    ║
║    │                                                                     ║
║    ├── PromptManager.get_system_prompt()                                 ║
║    │       reads ai/prompts/<agent>_prompt.md                           ║
║    │       injects security preamble + Pydantic JSON schema             ║
║    │                                                                     ║
║    ├── PromptManager.build_user_prompt(evidence, context)               ║
║    │       formats evidence envelope as JSON                            ║
║    │       adds prior agent context (if any)                            ║
║    │                                                                     ║
║    ├── LLMGateway.generate(                                             ║
║    │       model_name="nvidia/nemotron-3-super-120b-a12b:free",                     ║
║    │       system_prompt=system,                                        ║
║    │       user_prompt=user,                                            ║
║    │       response_schema=ManifestAnalysisResult,                      ║
║    │   )                                                                 ║
║    │       │                                                             ║
║    │       ├── ModelRouter.resolve(model_name)                          ║
║    │       │       → AnthropicAdapter                                  ║
║    │       │                                                             ║
║    │       ├── AnthropicAdapter.complete(ChatCompletionRequest)         ║
║    │       │       → HTTP POST /v1/messages                             ║
║    │       │       → ChatCompletionResponse(content, usage, ...)        ║
║    │       │                                                             ║
║    │       └── _try_parse(content, ManifestAnalysisResult)              ║
║    │               → pydantic model OR self-correction retry            ║
║    │                                                                     ║
║    ├── ResponseValidator.validate(raw_text, evidence)                   ║
║    │       JSONRepair.repair(text)                                      ║
║    │           → direct_parse | fence_extract | brace_extract           ║
║    │           → trailing_comma_fix | truncation_repair                 ║
║    │       SchemaValidator._validate_dict(data)                         ║
║    │           → Pydantic validation                                    ║
║    │           → type coercion                                          ║
║    │           → partial model fallback                                 ║
║    │       Business rules:                                              ║
║    │           → confidence range check                                 ║
║    │           → score range check                                      ║
║    │           → MITRE coverage warnings                                ║
║    │           → evidence reference cross-validation                    ║
║    │                                                                     ║
║    └── GraphState.agent_results["manifest_agent"] = result.model_dump() ║
║                                                                          ║
║  Schemas used per agent:                                                 ║
║    manifest_agent     → ManifestAnalysisResult   (schemas/results.py)   ║
║    permission_agent   → PermissionAnalysisResult (schemas/results.py)   ║
║    code_agent         → CodeAnalysisResult       (schemas/results.py)   ║
║    api_agent          → APIAnalysisResult        (schemas/results.py)   ║
║    network_agent      → NetworkAnalysisResult    (schemas/results.py)   ║
║    threat_intel_agent → ThreatIntelAnalysisResult(schemas/results.py)   ║
║    risk_agent         → RiskAssessmentResult     (schemas/results.py)   ║
║    report_agent       → ReportResult             (schemas/results.py)   ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
