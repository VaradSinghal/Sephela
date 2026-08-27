"""Base agent infrastructure for Sephela GenAI analysis."""

from __future__ import annotations

import abc
import contextvars
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ValidationError

from ai.schemas.base import Finding
from ai.validation.response_validator import ResponseValidator
from ai.validation.schema_validator import ValidationReport

#: Exact token usage from the most recent LLM turn, published by ``_call_llm`` and
#: consumed by ``execute``.  A ContextVar rather than an instance attribute because
#: agent instances are built once (ai/orchestration/workflow.py) and their LangGraph
#: nodes run concurrently — instance state would be written by whichever branch
#: happened to finish last.  Each node runs in its own task, so each sees its own
#: copy.  Unset (None) means the caller overrode ``_call_llm`` and we fall back to
#: estimating.
_LAST_CALL_TOKENS: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "sephela_llm_tokens", default=None
)


class AgentStatus(str, Enum):
    """Agent execution status."""

    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    partial = "partial"


class AgentError(BaseModel):
    """Agent error details."""

    agent: str
    error_type: str
    message: str
    recoverable: bool = True
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    """Standardized agent execution result."""

    agent_name: str
    status: AgentStatus
    output: Any = None
    findings: list[Finding] = field(default_factory=list)
    errors: list[AgentError] = field(default_factory=list)
    execution_time_ms: int = 0
    tokens_used: int = 0
    model_name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class OutputRejectedError(RuntimeError):
    """The LLM output parsed but violated a business rule, so it is worth retrying.

    Distinct from ``ValidationError``: pydantic rejected nothing here. The shape was
    right and the content was not.
    """


def _validation_trace(report: ValidationReport) -> dict[str, Any]:
    """Auditable summary of what the validator did to one response.

    Kept small on purpose — it is stored per agent on every job, so it records the
    verdict and the issues, not the raw text that produced them.
    """
    return {
        "status": report.status.value,
        "repair_strategy": report.repair_strategy,
        "errors": [f"{i.field_path}: {i.message}" for i in report.errors],
        "warnings": [f"{i.field_path}: {i.message}" for i in report.warnings],
    }


T = TypeVar("T", bound=BaseModel)


class AgentConfig(BaseModel):
    """Agent configuration."""

    name: str
    model: str = "nvidia/nemotron-3-super-120b-a12b:free"
    temperature: float = 0.1
    max_tokens: int = 8192
    timeout_seconds: int = 120
    max_retries: int = 2
    retry_delay_seconds: int = 5
    system_prompt: str = ""
    output_schema: type[BaseModel] | None = None
    enabled: bool = True
    # Phase 12: append retrieved reference knowledge to this agent's prompt.
    # Per-agent because not every agent benefits — a purely structural agent
    # spends its budget better on evidence than on background material.
    use_knowledge: bool = True


class BaseAgent(abc.ABC, Generic[T]):
    """Abstract base class for all analysis agents.

    Phase 12 adds an optional ``knowledge`` service. Retrieved reference material
    is appended to the prompt *after* ``build_prompt`` rather than being passed
    into it, for two reasons:

    - every agent gains RAG without touching its prompt-building code, so there is
      one place where the reference block's framing and delimiters are decided;
    - the block therefore always lands *after* the evidence, which is the ordering
      that keeps the model's attention on the sample it is analysing rather than on
      the background reading (see ``ai/rag/context.py``).

    A missing or disabled service is a no-op, so the prompt path is identical
    whether RAG is configured or not.
    """

    def __init__(self, config: AgentConfig, llm_client: Any = None, knowledge: Any = None):
        self.config = config
        self.llm_client = llm_client
        self.knowledge = knowledge
        self._validate_config()
        # Built once: it is stateless, and _validate_config has already guaranteed
        # output_schema is set.
        self._validator = ResponseValidator(config.output_schema)  # type: ignore[arg-type]

    def _validate_config(self) -> None:
        if not self.config.name:
            raise ValueError("Agent name is required")
        if self.config.output_schema is None:
            raise ValueError(f"{self.config.name}: output_schema is required")

    @abc.abstractmethod
    def build_prompt(self, evidence: dict[str, Any], context: dict[str, Any]) -> str:
        """Build the analysis prompt from evidence and context."""
        pass

    @abc.abstractmethod
    def parse_output(self, raw_output: str) -> T:
        """Parse and validate raw LLM output against schema."""
        pass

    def extract_findings(self, output: T) -> list[Finding]:
        """Extract standardized findings from agent output."""
        findings = []
        if hasattr(output, "findings") and isinstance(output.findings, list):
            findings.extend(output.findings)
        return findings

    async def execute(self, evidence: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        """Execute the agent with retries and validation."""
        start_time = time.time()
        errors: list[AgentError] = []

        # Retrieved once, outside the retry loop: the corpus does not change
        # between attempts, and re-embedding the same query per retry would pay
        # for identical results.
        knowledge_block, knowledge_trace = await self._retrieve_knowledge(evidence, context)
        if knowledge_block:
            context = {**context, "reference_knowledge": knowledge_block}

        for attempt in range(self.config.max_retries + 1):
            last_attempt = attempt == self.config.max_retries
            try:
                prompt = self.build_prompt(evidence, context)
                if knowledge_block:
                    prompt = f"{prompt}\n\n{knowledge_block}"

                # Cleared before the call so a stale reading from an earlier attempt
                # can never be attributed to this one.
                _LAST_CALL_TOKENS.set(None)
                raw_output = await self._call_llm(prompt)

                parsed, report = self._validate_output(raw_output, evidence)

                # Business-rule errors — a confidence outside [0, 1], a score outside
                # [0, 100] — mean the output parsed but says something impossible.
                # Worth another turn, but not worth discarding on the final one: a
                # usable result with a flagged field beats no result at all, so it
                # degrades to `partial` the way the engine stages do.
                blocking = report.errors if report is not None else []
                if blocking and not last_attempt:
                    raise OutputRejectedError(
                        "; ".join(f"{i.field_path}: {i.message}" for i in blocking)
                    )

                findings = self.extract_findings(parsed)

                execution_time = int((time.time() - start_time) * 1000)

                # Carried so a finding that leaned on background knowledge can be
                # audited: which documents were in the prompt, whether retrieval was
                # degraded, and what the validator had to say about the output.
                metadata: dict[str, Any] = {}
                if knowledge_trace:
                    metadata["rag"] = knowledge_trace
                if report is not None:
                    metadata["validation"] = _validation_trace(report)

                return AgentResult(
                    agent_name=self.config.name,
                    status=AgentStatus.partial if blocking else AgentStatus.completed,
                    output=parsed,
                    findings=findings,
                    errors=errors,
                    execution_time_ms=execution_time,
                    tokens_used=self._tokens_used(prompt, raw_output),
                    model_name=self.config.model,
                    metadata=metadata,
                )

            except ValidationError as e:
                error = AgentError(
                    agent=self.config.name,
                    error_type="ValidationError",
                    message=f"Output validation failed: {e}",
                    recoverable=True,
                    context={"attempt": attempt + 1, "errors": e.errors()},
                )
                errors.append(error)

            except Exception as e:
                error = AgentError(
                    agent=self.config.name,
                    error_type=type(e).__name__,
                    message=str(e),
                    recoverable=attempt < self.config.max_retries,
                    context={"attempt": attempt + 1},
                )
                errors.append(error)

            if attempt < self.config.max_retries:
                await self._retry_delay(attempt)

        # All retries exhausted
        execution_time = int((time.time() - start_time) * 1000)
        return AgentResult(
            agent_name=self.config.name,
            status=AgentStatus.failed if errors else AgentStatus.partial,
            errors=errors,
            execution_time_ms=execution_time,
        )

    async def _retrieve_knowledge(
        self, evidence: dict[str, Any], context: dict[str, Any]
    ) -> tuple[str, dict[str, Any] | None]:
        """Fetch the reference-knowledge block for this agent's prompt.

        Never raises. Background knowledge is an enhancement, so a broken or
        unreachable knowledge service must degrade the analysis rather than fail
        it — the same partial-success principle the engine stages follow.
        """
        if self.knowledge is None or not self.config.use_knowledge:
            return "", None

        try:
            block = await self.knowledge.context_for(
                evidence,
                findings=context.get("findings") or context.get("prior_findings"),
                agent=self.config.name,
            )
        except Exception as exc:  # noqa: BLE001
            return "", {"degraded": True, "error": f"{type(exc).__name__}: {exc}"}

        trace = getattr(self.knowledge, "last_summary", {}).get(self.config.name)
        return block or "", trace

    async def _call_llm(self, prompt: str) -> str:
        """Run one LLM turn and return the raw text. Override for custom clients.

        Two client shapes are accepted, because both exist in this codebase and a
        caller should not have to care which one it holds:

        - ``generate(...)`` — ``ai.llm.factory.LLMGateway``, the interface the
          orchestrator actually wires in. The agent's ``output_schema`` is passed
          through so the gateway puts the provider in JSON mode and runs its own
          self-correction turn on a schema miss. That is a *cheaper* retry than the
          one in ``execute``: it re-prompts with the validation error instead of
          rebuilding the prompt and paying for the evidence tokens again.
        - ``complete(prompt)`` — the ``ai.llm.client.LLMClient`` ABC, which knows
          nothing about schemas and so gets the prompt as-is.

        Exact token usage is published on ``_LAST_CALL_TOKENS`` rather than
        returned, so overriding this method stays a one-line job.
        """
        if self.llm_client is None:
            raise RuntimeError(
                f"{self.config.name}: no llm_client configured. Pass one to the "
                f"constructor or override _call_llm."
            )

        if hasattr(self.llm_client, "generate"):
            result = await self.llm_client.generate(
                model_name=self.config.model,
                system_prompt=self.config.system_prompt,
                user_prompt=prompt,
                response_schema=self.config.output_schema,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                timeout_s=float(self.config.timeout_seconds),
            )
            usage = getattr(result, "usage", None)
            _LAST_CALL_TOKENS.set(getattr(usage, "total_tokens", None))
            return str(result.content)

        if hasattr(self.llm_client, "complete"):
            response = await self.llm_client.complete(prompt)
            _LAST_CALL_TOKENS.set(getattr(response, "tokens_used", None))
            return str(response.content)

        raise TypeError(
            f"{self.config.name}: llm_client of type "
            f"{type(self.llm_client).__name__} exposes neither generate() nor "
            f"complete(); cannot call it."
        )

    def _validate_output(
        self, raw_output: str, evidence: dict[str, Any]
    ) -> tuple[T, ValidationReport | None]:
        """Turn raw LLM text into a validated model.

        ``ResponseValidator`` runs first because it is strictly stronger than the
        per-agent ``parse_output``: seven JSON-repair strategies and type coercion
        rather than ``json.loads`` plus one code-fence regex, and on top of that the
        business rules — confidence and score bounds, MITRE mappings on high-severity
        findings, and ``_check_evidence_refs``, which is what stops an agent citing an
        extractor that never ran.

        ``parse_output`` stays the fallback and the extension point: an agent that
        needs to do something the validator cannot still gets its turn, and its
        exception still drives the retry loop.
        """
        report = self._validator.validate(
            raw_output, evidence=evidence, agent_name=self.config.name
        )
        if report.is_usable and report.model_instance is not None:
            return report.model_instance, report  # type: ignore[return-value]
        return self.parse_output(raw_output), None

    def _tokens_used(self, prompt: str, output: str) -> int:
        """Exact usage when the provider reported it, else an estimate.

        A custom ``_call_llm`` publishes nothing, so it lands on the estimate.
        """
        reported = _LAST_CALL_TOKENS.get()
        if reported is not None:
            return reported
        return self._estimate_tokens(prompt, output)

    def _estimate_tokens(self, prompt: str, output: str) -> int:
        """Rough token estimation."""
        return (len(prompt) + len(output)) // 4

    async def _retry_delay(self, attempt: int) -> None:
        """Wait before retry with exponential backoff."""
        import asyncio

        delay = self.config.retry_delay_seconds * (2**attempt)
        await asyncio.sleep(delay)


class AgentRegistry:
    """Registry for managing and executing agents."""

    def __init__(self):
        self._agents: dict[str, BaseAgent] = {}

    def register(self, agent: BaseAgent) -> None:
        self._agents[agent.config.name] = agent

    def get(self, name: str) -> BaseAgent | None:
        return self._agents.get(name)

    def list_agents(self) -> list[str]:
        return list(self._agents.keys())

    async def execute_agent(
        self, name: str, evidence: dict[str, Any], context: dict[str, Any]
    ) -> AgentResult:
        agent = self._agents.get(name)
        if not agent:
            raise ValueError(f"Agent '{name}' not found")
        if not agent.config.enabled:
            return AgentResult(
                agent_name=name,
                status=AgentStatus.partial,
                errors=[AgentError(agent=name, error_type="Disabled", message="Agent is disabled")],
            )
        return await agent.execute(evidence, context)

    async def execute_pipeline(
        self, agent_names: list[str], evidence: dict[str, Any], context: dict[str, Any]
    ) -> list[AgentResult]:
        """Execute multiple agents in sequence, passing outputs forward."""
        results = []
        accumulated_context = {**context}

        for name in agent_names:
            result = await self.execute_agent(name, evidence, accumulated_context)
            results.append(result)

            # Add successful output to context for next agent
            if result.status == AgentStatus.completed and result.output:
                accumulated_context[f"{name}_output"] = (
                    result.output.model_dump()
                    if hasattr(result.output, "model_dump")
                    else result.output
                )
                accumulated_context[f"{name}_findings"] = [f.model_dump() for f in result.findings]

        return results
