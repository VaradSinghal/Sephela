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
from ai.schemas.permissions import PermissionsAnalysis
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


class BaseAgent(abc.ABC, Generic[T]):
    """Abstract base class for all analysis agents."""
    
    def __init__(self, config: AgentConfig, llm_client: Any = None):
        self.config = config
        self.llm_client = llm_client
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
        
        for attempt in range(self.config.max_retries + 1):
            try:
                prompt = self.build_prompt(evidence, context)
                
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