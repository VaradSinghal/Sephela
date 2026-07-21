"""LangGraph orchestration graph for multi-agent Android malware analysis."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.base import BaseCheckpointSaver

from ai.orchestration.state import AgentState, PipelineStatus
from ai.agents.base import AgentRegistry, BaseAgent, AgentConfig, AgentResult


@dataclass
class AnalysisState:
    """Complete state for the analysis pipeline."""
    job_id: str
    sample_sha256: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    agent_results: Dict[str, AgentResult] = field(default_factory=dict)
    all_findings: List[Any] = field(default_factory=list)
    status: PipelineStatus = PipelineStatus.PENDING
    current_agent: Optional[str] = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 2


def create_agent_node(agent: BaseAgent) -> Callable:
    """Create a LangGraph node function for an agent."""
    
    async def agent_node(state: AnalysisState) -> dict:
        updates = {
            "current_agent": agent.config.name,
            "status": PipelineStatus.RUNNING,
        }
        
        try:
            result = await agent.execute(state.evidence, state.context)
            new_results = dict(state.agent_results)
            new_results[agent.config.name] = result
            updates["agent_results"] = new_results
            
            if result.status.value in ("completed", "partial"):
                updates["all_findings"] = state.all_findings + result.findings
                new_context = dict(state.context)
                new_context[f"{agent.config.name}_output"] = result.output.model_dump() if result.output else {}
                new_context[f"{agent.config.name}_findings"] = [f.model_dump() for f in result.findings]
                updates["context"] = new_context
            else:
                updates["error"] = f"{agent.config.name}: {result.errors}"
                updates["retry_count"] = state.retry_count + 1
                
        except Exception as e:
            updates["error"] = f"{agent.config.name}: {str(e)}"
            updates["retry_count"] = state.retry_count + 1
        
        return updates
    
    return agent_node


def should_retry(state: AnalysisState) -> str:
    """Determine if we should retry the current agent or continue."""
    if state.error and state.retry_count < state.max_retries:
        return "retry"
    elif state.error:
        state.status = PipelineStatus.FAILED
        return "error"
    return "continue"


def create_analysis_graph(registry: AgentRegistry, checkpointer: Optional[BaseCheckpointSaver] = None) -> StateGraph:
    """Create the complete analysis pipeline graph."""
    
    workflow = StateGraph(AnalysisState)
    
    # Define agent execution order
    agent_order = [
        "manifest_agent",
        "permission_agent", 
        "code_agent",
        "api_agent",
        "network_agent",
        "threat_intel_agent",
        "risk_agent",
        "report_agent",
    ]
    
    # Add nodes for each agent
    for agent_name in agent_order:
        agent = registry.get(agent_name)
        if agent and agent.config.enabled:
            workflow.add_node(agent_name, create_agent_node(agent))
    
    # Set entry point
    workflow.set_entry_point(agent_order[0])
    
    # Add conditional edges for retry logic
    for agent_name in agent_order:
        agent = registry.get(agent_name)
        if agent and agent.config.enabled:
            # Find next enabled agent
            next_agent = END
            for next_name in agent_order[agent_order.index(agent_name) + 1:]:
                next_obj = registry.get(next_name)
                if next_obj and next_obj.config.enabled:
                    next_agent = next_name
                    break

            workflow.add_conditional_edges(
                agent_name,
                should_retry,
                {
                    "retry": agent_name,
                    "continue": next_agent,
                    "error": END,
                }
            )
    
    # Compile with checkpointer
    return workflow.compile(checkpointer=checkpointer)


async def run_analysis_pipeline(
    graph,
    job_id: str,
    sample_sha256: str,
    evidence: Dict[str, Any],
    context: Dict[str, Any] = None,
    config: Dict[str, Any] = None,
) -> AnalysisState:
    """Run the complete analysis pipeline."""
    
    initial_state = AnalysisState(
        job_id=job_id,
        sample_sha256=sample_sha256,
        evidence=evidence,
        context=context or {},
    )
    
    final_state = await graph.ainvoke(initial_state, config=config or {})
    return final_state