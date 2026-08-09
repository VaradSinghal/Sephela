"""Base agent infrastructure for Sephela GenAI analysis."""

from __future__ import annotations

import abc
import json
import time
from typing import Any, Generic, TypeVar
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ValidationError

from ai.schemas.base import Finding, Severity, EvidenceRef
from ai.schemas.manifest import ManifestAnalysis
from ai.schemas.permission import PermissionAnalysis
from ai.schemas.code import CodeAnalysis
from ai.schemas.network import NetworkAnalysis
from ai.schemas.threat_intel import ThreatIntelAnalysis
from ai.schemas.risk import RiskAnalysis
from ai.schemas.report import AnalysisReport


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
    timestamp: datetime = field(default_factory=datetime.utcnow)
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


T = TypeVar('T', bound=BaseModel)


class AgentConfig(BaseModel):
    """Agent configuration."""
    name: str
    model: str = "claude-3-5-sonnet-20241022"
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
        if hasattr(output, 'findings') and isinstance(output.findings, list):
            findings.extend(output.findings)
        return findings
    
    async def execute(self, evidence: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        """Execute the agent with retries and validation."""
        start_time = time.time()
        errors = []

        # Retrieved once, outside the retry loop: the corpus does not change
        # between attempts, and re-embedding the same query per retry would pay
        # for identical results.
        knowledge_block, knowledge_trace = await self._retrieve_knowledge(evidence, context)
        if knowledge_block:
            context = {**context, "reference_knowledge": knowledge_block}

        for attempt in range(self.config.max_retries + 1):
            try:
                prompt = self.build_prompt(evidence, context)
                if knowledge_block:
                    prompt = f"{prompt}\n\n{knowledge_block}"

                # Call LLM
                raw_output = await self._call_llm(prompt)
                
                # Parse and validate
                parsed = self.parse_output(raw_output)
                
                # Extract findings
                findings = self.extract_findings(parsed)
                
                execution_time = int((time.time() - start_time) * 1000)
                
                return AgentResult(
                    agent_name=self.config.name,
                    status=AgentStatus.completed,
                    output=parsed,
                    findings=findings,
                    execution_time_ms=execution_time,
                    tokens_used=self._estimate_tokens(prompt, raw_output),
                    model_name=self.config.model,
                    # Carried so a finding that leaned on background knowledge can
                    # be audited: which documents were in the prompt, and whether
                    # retrieval was degraded at the time.
                    metadata={"rag": knowledge_trace} if knowledge_trace else {},
                )
                
            except ValidationError as e:
                error = AgentError(
                    agent=self.config.name,
                    error_type="ValidationError",
                    message=f"Output validation failed: {e}",
                    recoverable=True,
                    context={"attempt": attempt + 1, "errors": e.errors()}
                )
                errors.append(error)
                
            except Exception as e:
                error = AgentError(
                    agent=self.config.name,
                    error_type=type(e).__name__,
                    message=str(e),
                    recoverable=attempt < self.config.max_retries,
                    context={"attempt": attempt + 1}
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
        """Call the LLM client. Override for custom clients."""
        if self.llm_client is None:
            raise RuntimeError("LLM client not configured")
        
        # This is a placeholder - implement based on your LLM client
        # Example for Anthropic:
        # response = await self.llm_client.messages.create(...)
        # return response.content[0].text
        
        # For now, raise not implemented
        raise NotImplementedError("_call_llm must be implemented or llm_client provided")
    
    def _estimate_tokens(self, prompt: str, output: str) -> int:
        """Rough token estimation."""
        return (len(prompt) + len(output)) // 4
    
    async def _retry_delay(self, attempt: int) -> None:
        """Wait before retry with exponential backoff."""
        import asyncio
        delay = self.config.retry_delay_seconds * (2 ** attempt)
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
    
    async def execute_agent(self, name: str, evidence: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        agent = self._agents.get(name)
        if not agent:
            raise ValueError(f"Agent '{name}' not found")
        if not agent.config.enabled:
            return AgentResult(
                agent_name=name,
                status=AgentStatus.partial,
                errors=[AgentError(agent=name, error_type="Disabled", message="Agent is disabled")]
            )
        return await agent.execute(evidence, context)
    
    async def execute_pipeline(self, agent_names: list[str], evidence: dict[str, Any], context: dict[str, Any]) -> list[AgentResult]:
        """Execute multiple agents in sequence, passing outputs forward."""
        results = []
        accumulated_context = {**context}
        
        for name in agent_names:
            result = await self.execute_agent(name, evidence, accumulated_context)
            results.append(result)
            
            # Add successful output to context for next agent
            if result.status == AgentStatus.completed and result.output:
                accumulated_context[f"{name}_output"] = result.output.model_dump() if hasattr(result.output, 'model_dump') else result.output
                accumulated_context[f"{name}_findings"] = [f.model_dump() for f in result.findings]
        
        return results