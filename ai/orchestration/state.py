"""Orchestration state definitions for LangGraph pipeline."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4


class PipelineStatus(str, Enum):
    """Pipeline execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"


class AgentStatus(str, Enum):
    """Individual agent execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"


@dataclass
class AgentState:
    """State of a single agent execution."""
    name: str
    status: AgentStatus = AgentStatus.PENDING
    output: Optional[Dict[str, Any]] = None
    findings: List[Any] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    tokens_used: int = 0
    retry_count: int = 0


@dataclass
class PipelineState:
    """Complete pipeline execution state."""
    job_id: str
    sample_sha256: str
    agents: Dict[str, AgentState] = field(default_factory=dict)
    all_findings: List[Any] = field(default_factory=list)
    status: PipelineStatus = PipelineStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_agent_state(self, name: str) -> AgentState:
        """Add or get agent state."""
        if name not in self.agents:
            self.agents[name] = AgentState(name=name)
        return self.agents[name]

    def get_agent_status(self, name: str) -> AgentStatus:
        """Get agent status."""
        return self.agents.get(name, AgentState(name=name)).status

    def is_complete(self) -> bool:
        """Check if pipeline is complete."""
        return self.status in (PipelineStatus.COMPLETED, PipelineStatus.FAILED, PipelineStatus.CANCELLED)

    def get_summary(self) -> Dict[str, Any]:
        """Get pipeline summary."""
        return {
            "job_id": self.job_id,
            "sample_sha256": self.sample_sha256,
            "status": self.status.value,
            "agents": {name: agent.status.value for name, agent in self.agents.items()},
            "total_findings": len(self.all_findings),
            "duration_seconds": (self.completed_at or datetime.utcnow() - self.created_at).total_seconds() if self.completed_at else None,
            "error": self.error,
        }