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
    
    async def agent_node(state: AnalysisState) -> AnalysisState:
        state.current_agent = agent.config.name
        state.status = PipelineStatus.RUNNING
        
        try:
            result = await agent.execute(state.evidence, state.context)
            state.agent_results[agent.config.name] = result
            
            if result.status.value == "completed":
                state.all_findings.extend(result.findings)
                state.context[f"{agent.config.name}_output"] = result.output.model_dump() if result.output else {}
                state.context[f"{agent.config.name}_findings"] = [f.model_dump() for f in result.findings]
            elif result.status.value == "partial":
                state.all_findings.extend(result.findings)
                state.context[f"{agent.config.name}_output"] = result.output.model_dump() if result.output else {}
                state.context[f"{agent.config.name}_findings"] = [f.model_dump() for f in result.findings]
            else:
                state.error = f"{agent.config.name}: {result.errors}"
                state.retry_count += 1
                
        except Exception as e:
            state.error = f"{agent.config.name}: {str(e)}"
            state.retry_count += 1
        
        return state
    
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
    
    # Add edges
    for i, agent_name in enumerate(agent_order):
        agent = registry.get(agent_name)
        if not agent or not agent.config.enabled:
            continue
            
        if i == 0:
            workflow.set_entry_point(agent_name)
        else:
            prev_agent = agent_order[i - 1]
            prev = registry.get(prev_agent)
            if prev and prev.config.enabled:
                workflow.add_edge(prev_agent, agent_name)
    
    # Add conditional edges for retry logic
    for agent_name in agent_order:
        agent = registry.get(agent_name)
        if agent and agent.config.enabled:
            workflow.add_conditional_edges(
                agent_name,
                should_retry,
                {
                    "retry": agent_name,
                    "continue": agent_order[agent_order.index(agent_name) + 1] if agent_order.index(agent_name) + 1 < len(agent_order) else END,
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