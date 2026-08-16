"""Sephela GenAI Subsystem — multi-agent Android malware analysis.

The entry points, in increasing order of how much you have to wire yourself:

    SephelaAnalysisPipeline  — build from env, hand it evidence, get a report
    PipelineRunner           — same graph, plus checkpointing and resume
    build_workflow           — the compiled LangGraph, for callers that own
                               their own agent wiring and invocation config
"""

from ai.agents.api import APIAgent
from ai.agents.base import AgentResult, BaseAgent
from ai.agents.code import CodeAgent
from ai.agents.manifest import ManifestAgent
from ai.agents.network import NetworkAgent
from ai.agents.permission import PermissionAgent
from ai.agents.report import ReportAgent
from ai.agents.risk import RiskAgent
from ai.agents.threat_intel import ThreatIntelAgent
from ai.orchestration.runner import PipelineRunner, PipelineRunResult
from ai.orchestration.workflow import WorkflowConfig, build_workflow

__all__ = [
    "APIAgent",
    "AgentResult",
    "BaseAgent",
    "CodeAgent",
    "ManifestAgent",
    "NetworkAgent",
    "PermissionAgent",
    "PipelineRunResult",
    "PipelineRunner",
    "ReportAgent",
    "RiskAgent",
    "ThreatIntelAgent",
    "WorkflowConfig",
    "build_workflow",
]

__version__ = "1.0.0"
