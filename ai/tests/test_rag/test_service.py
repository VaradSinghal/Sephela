"""The KnowledgeService façade and its agent integration.

End-to-end coverage of the path an agent actually takes: evidence in, a rendered
reference block out, with the feature flag and the failure behaviour that the
surrounding pipeline depends on.
"""

from __future__ import annotations

import pytest

from ai.agents.base import AgentConfig, AgentStatus, BaseAgent
from ai.rag.embeddings import HashingEmbedder
from ai.rag.service import (
    KnowledgeService,
    build_embedder,
    build_knowledge_service,
    build_store,
)
from ai.rag.store import InMemoryVectorStore
from ai.schemas.manifest import ManifestAnalysis
from ai.tests.test_rag.conftest import build_loaded_service

pytestmark = pytest.mark.anyio

# Evidence shaped like a real banking-trojan sample: accessibility + SMS + overlay.
TROJAN_EVIDENCE = {
    "permissions": {
        "permissions": [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.RECEIVE_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ]
    }
}
TROJAN_FINDINGS = [
    {"type": "permission", "mitre": ["T1417.001"], "owasp_mobile": ["M1"]},
    {
        "type": "family_attribution",
        "detail": "Attributed to malware family 'cerberus' by bazaar, otx",
    },
]


class TestContextForAgent:
    async def test_relevant_knowledge_reaches_the_prompt_block(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        service = await build_loaded_service(store, embedder)

        block = await service.context_for(
            TROJAN_EVIDENCE, findings=TROJAN_FINDINGS, agent="permission_agent"
        )

        assert "REFERENCE_KNOWLEDGE" in block
        assert "accessibility" in block.lower()

    async def test_the_agent_profile_shapes_what_is_retrieved(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        # The report agent wants the playbook; the permission agent should not be
        # spending its budget on escalation guidance.
        service = await build_loaded_service(store, embedder)

        report_block = await service.context_for(
            TROJAN_EVIDENCE, findings=TROJAN_FINDINGS, agent="report_agent"
        )
        permission_block = await service.context_for(
            TROJAN_EVIDENCE, findings=TROJAN_FINDINGS, agent="permission_agent"
        )

        assert "playbook" in report_block.lower()
        assert "playbook" not in permission_block.lower()

    async def test_the_retrieval_is_traced_for_auditing(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        service = await build_loaded_service(store, embedder)
        await service.context_for(TROJAN_EVIDENCE, findings=TROJAN_FINDINGS, agent="permission_agent")

        trace = service.last_summary["permission_agent"]
        assert trace["retrieved"] >= 1
        assert trace["sources"]
        assert trace["degraded"] is False

    async def test_an_empty_corpus_yields_an_empty_block(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        service = KnowledgeService(store=store, embedder=embedder)
        assert await service.context_for(TROJAN_EVIDENCE) == ""

    async def test_the_feature_flag_short_circuits_retrieval(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        service = await build_loaded_service(store, embedder)
        service.enabled = False

        assert await service.context_for(TROJAN_EVIDENCE, findings=TROJAN_FINDINGS) == ""
        # Not even a query was built, so nothing was traced.
        assert service.last_summary == {}


class TestConfiguration:
    def test_the_default_embedder_needs_no_credentials(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.delenv("RAG_EMBEDDING_MODEL", raising=False)
        embedder = build_embedder()
        assert embedder.dimensions == 512

    def test_setting_a_model_selects_the_remote_embedder(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setenv("RAG_EMBEDDING_MODEL", "text-embedding-3-small")
        embedder = build_embedder()
        assert embedder.inner.name == "openai_compatible"  # type: ignore[attr-defined]

    def test_the_default_store_is_in_memory(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.delenv("RAG_VECTOR_BACKEND", raising=False)
        assert isinstance(build_store(512), InMemoryVectorStore)

    def test_qdrant_can_be_selected(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setenv("RAG_VECTOR_BACKEND", "qdrant")
        monkeypatch.setenv("QDRANT_URL", "http://qdrant:6333")
        store = build_store(512)
        assert store.url == "http://qdrant:6333"  # type: ignore[attr-defined]

    async def test_build_ingests_the_bundled_corpus_by_default(self) -> None:
        service = await build_knowledge_service(
            store=InMemoryVectorStore(), embedder=HashingEmbedder(dimensions=256)
        )
        assert await service.count() > 0

    async def test_build_can_skip_ingestion(self) -> None:
        service = await build_knowledge_service(
            store=InMemoryVectorStore(),
            embedder=HashingEmbedder(dimensions=256),
            ingest=False,
        )
        assert await service.count() == 0

    async def test_an_ingestion_failure_does_not_break_construction(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        # An empty corpus degrades the analysis; raising here would break the
        # whole AI stage.
        service = await build_knowledge_service(
            store=InMemoryVectorStore(),
            embedder=HashingEmbedder(dimensions=256),
            corpus_dir="/nonexistent/corpus/path",
        )
        assert await service.count() == 0

    async def test_the_flag_is_read_from_the_environment(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setenv("RAG_ENABLED", "false")
        service = await build_knowledge_service(
            store=InMemoryVectorStore(), embedder=HashingEmbedder(dimensions=256)
        )
        assert service.enabled is False
        # Disabled means the corpus is not even loaded.
        assert await service.count() == 0


class StubAgent(BaseAgent[ManifestAnalysis]):
    """Minimal agent that records the prompt it was asked to send."""

    def __init__(self, knowledge=None, *, use_knowledge: bool = True) -> None:  # type: ignore[no-untyped-def]
        super().__init__(
            AgentConfig(
                name="permission_agent",
                output_schema=ManifestAnalysis,
                max_retries=0,
                use_knowledge=use_knowledge,
            ),
            llm_client=object(),
            knowledge=knowledge,
        )
        self.prompt_seen = ""

    def build_prompt(self, evidence, context):  # type: ignore[no-untyped-def]
        return "EVIDENCE BLOCK: analyse these permissions."

    def parse_output(self, raw_output):  # type: ignore[no-untyped-def]
        return ManifestAnalysis(package_name="com.example.test")

    async def _call_llm(self, prompt: str) -> str:
        self.prompt_seen = prompt
        return "{}"


class ExplodingKnowledge:
    last_summary: dict[str, dict[str, object]] = {}

    async def context_for(self, evidence, *, findings=None, agent=None):  # type: ignore[no-untyped-def]
        raise ConnectionError("vector store unreachable")


class TestAgentIntegration:
    async def test_the_reference_block_is_appended_after_the_evidence(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        # Ordering matters: evidence first keeps the model's attention on the
        # sample rather than on the background reading.
        service = await build_loaded_service(store, embedder)
        agent = StubAgent(service)

        result = await agent.execute(TROJAN_EVIDENCE, {"findings": TROJAN_FINDINGS})

        assert result.status is AgentStatus.completed
        assert agent.prompt_seen.startswith("EVIDENCE BLOCK")
        assert "REFERENCE_KNOWLEDGE" in agent.prompt_seen
        assert agent.prompt_seen.index("EVIDENCE BLOCK") < agent.prompt_seen.index(
            "REFERENCE_KNOWLEDGE"
        )

    async def test_the_retrieval_trace_is_attached_to_the_result(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        service = await build_loaded_service(store, embedder)
        result = await StubAgent(service).execute(TROJAN_EVIDENCE, {"findings": TROJAN_FINDINGS})

        assert "rag" in result.metadata
        assert result.metadata["rag"]["retrieved"] >= 1

    async def test_an_agent_without_a_knowledge_service_is_unaffected(self) -> None:
        agent = StubAgent(None)
        result = await agent.execute(TROJAN_EVIDENCE, {})

        assert result.status is AgentStatus.completed
        assert agent.prompt_seen == "EVIDENCE BLOCK: analyse these permissions."
        assert result.metadata == {}

    async def test_per_agent_opt_out_is_respected(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        service = await build_loaded_service(store, embedder)
        agent = StubAgent(service, use_knowledge=False)

        await agent.execute(TROJAN_EVIDENCE, {"findings": TROJAN_FINDINGS})

        assert "REFERENCE_KNOWLEDGE" not in agent.prompt_seen

    async def test_a_knowledge_failure_degrades_rather_than_failing_the_agent(self) -> None:
        # Background knowledge is an enhancement; losing it must not fail analysis.
        agent = StubAgent(ExplodingKnowledge())

        result = await agent.execute(TROJAN_EVIDENCE, {})

        assert result.status is AgentStatus.completed
        assert "REFERENCE_KNOWLEDGE" not in agent.prompt_seen
        assert result.metadata["rag"]["degraded"] is True

    async def test_the_block_is_also_exposed_through_context(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        # Agents that want to place the block themselves can read it from context.
        service = await build_loaded_service(store, embedder)

        class ContextReadingAgent(StubAgent):
            def build_prompt(self, evidence, context):  # type: ignore[no-untyped-def]
                assert "reference_knowledge" in context
                return "EVIDENCE"

        await ContextReadingAgent(service).execute(TROJAN_EVIDENCE, {"findings": TROJAN_FINDINGS})
