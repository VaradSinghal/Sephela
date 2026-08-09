"""
Ingest the knowledge corpus into the configured vector store.

    python -m ai.rag                 # incremental — unchanged documents cost nothing
    python -m ai.rag --force         # re-embed everything (use when the model changes)
    python -m ai.rag --corpus path/  # ingest a different corpus directory

Exists as an ops entry point because ingestion is a deploy-time step for a Qdrant
deployment, and because the rejection list is the only place an operator learns why
a corpus file never appears in retrieval.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from ai.rag.service import build_knowledge_service


async def _run(corpus: str | None, force: bool) -> int:
    # Built without auto-ingestion so the report below reflects this run's work
    # rather than construction's.
    service = await build_knowledge_service(ingest=False)
    if not service.enabled:
        print("RAG is disabled (RAG_ENABLED=false); nothing ingested.")
        return 0

    report = await service.ingest(corpus, force=force)

    print(
        f"documents: {report.documents_seen} seen, "
        f"{report.documents_ingested} ingested, "
        f"{report.documents_unchanged} unchanged, "
        f"{report.documents_rejected} rejected"
    )
    print(f"chunks written: {report.chunks_written}")
    print(f"chunks in store: {await service.count()}")

    if report.rejections:
        print("\nrejected:")
        for path, reason in report.rejections:
            print(f"  {path}: {reason}")
        # Non-zero exit so a CI step or deploy hook notices a broken corpus file
        # instead of shipping a knowledge base that is quietly missing documents.
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m ai.rag", description=__doc__)
    parser.add_argument("--corpus", default=None, help="corpus directory (default: bundled)")
    parser.add_argument(
        "--force", action="store_true", help="re-embed unchanged documents"
    )
    parser.add_argument("--quiet", action="store_true", help="suppress log output")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
    )
    return asyncio.run(_run(args.corpus, args.force))


if __name__ == "__main__":
    sys.exit(main())
