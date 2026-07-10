"""Tests for orchestration graph."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from ai.orchestration.graph import (
    AnalysisState,
    create_agent_node,
    create_analysis_graph,
    run_analysis_pipeline,
    should_retry,
)
from ai.orchestration.state import PipelineStatus
from ai.agents.base import AgentRegistry, BaseAgent, AgentConfig, AgentResult, AgentStatus


class MockAgent(BaseAgent):
    """Mock agent for testing."""

    def __init__(self, name: str, should_fail: bool = False):
        config = AgentConfig(
            name=name,
            output_schema=dict,
        )
        super().__init__(config, None)
        self.should_fail = should_fail

    async def execute(self, evidence, context):
        if self.should_fail:
            return AgentResult(
                agent_name=self.config.name,
                status=AgentStatus.failed,
                errors=[MagicMock(message="Test error")],
            )
        return AgentResult(
            agent_name=self.config.name,
            status=AgentStatus.completed,
            output={"test": "data"},
            findings=[],
        )

    def build_prompt(self, evidence, context):
        return "test prompt"

    def parse_output(self, raw_output):
        return {"test": "data"}


@pytest.fixture
def mock_registry():
    """Create a mock agent registry."""
    registry = AgentRegistry()
    registry.register(MockAgent("manifest_agent"))
    registry.register(MockAgent("permission_agent"))
    registry.register(MockAgent("code_agent"))
    return registry


class TestAnalysisState:
    """Test AnalysisState dataclass."""

    def test_initial_state(self):
        state = AnalysisState(
            job_id="job_123",
            sample_sha256="a" * 64,
            evidence={"test": "data"},
            context={},
        )
        assert state.job_id == "job_123"
        assert state.sample_sha256 == "a" * 64
        assert state.status == PipelineStatus.PENDING
        assert state.current_agent is None
        assert state.error is None
        assert state.retry_count == 0

    def test_state_with_results(self):
        state = AnalysisState(
            job_id="job_123",
            sample_sha256="a" * 64,
            evidence={},
            context={},
            agent_results={"agent1": MagicMock()},
            all_findings=[MagicMock()],
        )
        assert len(state.agent_results) == 1
        assert len(state.all_findings) == 1


class TestCreateAgentNode:
    """Test agent node creation."""

    @pytest.mark.asyncio
    async def test_successful_agent_execution(self, mock_registry):
        agent = mock_registry.get("manifest_agent")
        node = create_agent_node(agent)

        state = AnalysisState(
            job_id="job_123",
            sample_sha256="a" * 64,
            evidence={},
            context={},
        )

        result = await node(state)

        assert result.status == PipelineStatus.RUNNING
        assert result.current_agent == "manifest_agent"
        assert "manifest_agent" in result.agent_results

    @pytest.mark.asyncio
    async def test_failed_agent_execution(self):
        agent = MockAgent("failing_agent", should_fail=True)
        node = create_agent_node(agent)

        state = AnalysisState(
            job_id="job_123",
            sample_sha256="a" * 64,
            evidence={},
            context={},
        )

        result = await node(state)

        assert result.error is not None
        assert result.retry_count == 1
        assert "failing_agent" in result.error


class TestShouldRetry:
    """Test retry logic."""

    def test_should_retry_within_limit(self):
        state = AnalysisState(
            job_id="job_123",
            sample_sha256="a" * 64,
            evidence={},
            context={},
            error="Test error",
            retry_count=1,
            max_retries=3,
        )
        assert should_retry(state) == "retry"

    def test_should_not_retry_exceeded(self):
        state = AnalysisState(
            job_id="job_123",
            sample_sha256="a" * 64,
            evidence={},
            context={},
            error="Test error",
            retry_count=3,
            max_retries=3,
        )
        assert should_retry(state) == "error"
        assert state.status == PipelineStatus.FAILED

    def test_continue_on_success(self):
        state = AnalysisState(
            job_id="job_123",
            sample_sha256="a" * 64,
            evidence={},
            context={},
            error=None,
            retry_count=0,
        )
        assert should_retry(state) == "continue"


class TestCreateAnalysisGraph:
    """Test graph creation."""

    def test_graph_creation(self, mock_registry):
        graph = create_analysis_graph(mock_registry)
        assert graph is not None

    def test_graph_has_all_agents(self, mock_registry):
        graph = create_analysis_graph(mock_registry)
        # Graph should be compiled
        assert hasattr(graph, "ainvoke")


class TestRunAnalysisPipeline:
    """Test pipeline execution."""

    @pytest.mark.asyncio
    async def test_pipeline_execution(self, mock_registry):
        with patch("ai.orchestration.graph.create_analysis_graph") as mock_create:
            mock_graph = AsyncMock()
            mock_graph.ainvoke = AsyncMock(return_value=AnalysisState(
                job_id="job_123",
                sample_sha256="a" * 64,
                evidence={},
                context={},
                status=PipelineStatus.COMPLETED,
            ))
            mock_create.return_value = mock_graph

            result = await run_analysis_pipeline(
                mock_graph,
                job_id="job_123",
                sample_sha256="a" * 64,
                evidence={"test": "data"},
            )

            assert result.job_id == "job_123"
            assert result.status == PipelineStatus.COMPLETED


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
```