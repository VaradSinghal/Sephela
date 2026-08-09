# Sephela RAG / Knowledge Service (Phase 12)

Retrieves curated threat-intelligence knowledge and injects it into agent prompts
as clearly-delimited reference material. Sits before LLM inference in DFD-3
(`docs/architecture/07-data-flow.md`).

```
evidence + findings
  → controlled-vocabulary query        (query.py — no raw sample strings)
  → embed                             (embeddings.py)
  → vector search, trust-filtered     (store.py / qdrant.py)
  → rank, diversify, budget           (retriever.py)
  → delimited prompt block            (context.py)
```

## The security constraint that shapes everything

`docs/architecture/09-security.md`: *"Retrieved RAG docs are trusted-source only;
sample-derived text is quarantined."*

Retrieval output lands in an LLM prompt. A knowledge base that could be poisoned
with text from an analyzed APK would be a persistent, cross-tenant prompt-injection
channel. The rule is enforced at three independent points:

| Point | Mechanism |
|---|---|
| Ingestion (`ingest.py`) | A document not declaring `trust: curated` or `trust: vendor` is refused **with a reason**. |
| Storage + retrieval (`store.py`, `qdrant.py`, `retriever.py`) | `trusted_only` filters, defaulted on; the retriever re-checks whatever the store returned. |
| Rendering (`context.py`) | Final trust gate; anything untrusted arriving here is dropped and logged at ERROR. |

Queries are built only from a **controlled vocabulary** — permission constants,
MITRE ids, Java-style API names, normalized family names, our own finding types.
Free text from a sample is dropped, so an attacker cannot steer which knowledge
documents get quoted by planting strings in their APK.

The prompt block additionally states that passages are *not* observations about the
sample, because a model handed a detailed trojan description will otherwise tend to
find that trojan.

## Zero configuration by default

- `HashingEmbedder` — deterministic bag-of-n-grams, no API key, no model download.
  Matches exact vocabulary (which is most of what this corpus is queried by); it
  cannot match paraphrases. Set `RAG_EMBEDDING_MODEL` for semantic recall.
- `InMemoryVectorStore` — brute-force cosine search. A real backend for a curated
  corpus of a few thousand chunks, not a stub. Set `RAG_VECTOR_BACKEND=qdrant`
  when it outgrows that.

## Retrieval behaviour worth knowing

- **Two-pass search** when a family is attributed: one family-filtered pass plus
  one general pass, merged. Filtering only on the family would exclude every
  general technique document.
- **Diversity cap** of 2 chunks per document, so a long family profile cannot fill
  every result slot with near-identical text.
- **Token budget** enforced, and truncation is reported — retrieved knowledge must
  not crowd out evidence.
- **Fails open**: a store outage sets `degraded` and returns nothing, never raises.

## Corpus format

Markdown with front matter, under `ai/rag/knowledge/`:

```markdown
---
title: Cerberus / Alien banking trojan family
kind: malware_family        # malware_family|technique|behavior_pattern|detection_rule|playbook|reference
trust: curated              # curated|vendor  (anything else is refused)
source: internal:threat-research
families: [cerberus, alien]
mitre: [T1417.001, T1626]
tags: [banking, overlay]
---

# Cerberus / Alien banking trojan family
...
```

Ingestion is incremental and content-hashed: re-running over an unchanged corpus
performs zero embedding calls, and an edited document has its old chunks deleted
before the new ones are written.

## Usage

```python
from ai.rag import build_knowledge_service

service = await build_knowledge_service()        # ingests the bundled corpus
block = await service.context_for(evidence, findings=findings, agent="permission_agent")
```

Agents get this automatically — `BaseAgent` appends the block after `build_prompt`,
so all eight agents benefit without changes, and the block always lands after the
evidence.

## Tests

```bash
pytest ai/tests/test_rag
```

Fully offline and deterministic: no network, no database, no clock dependence.
Qdrant and the remote embedder are driven through `httpx.MockTransport`.
