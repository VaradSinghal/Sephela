"""Object-storage abstraction.

A stable interface so the rest of the platform never depends on where bytes
live. Local filesystem backend for dev; S3-compatible backend for prod
(docs/architecture/01-tech-stack.md). Samples are addressed by content hash.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class StorageBackend(ABC):
    """Content-addressed blob storage."""

    @abstractmethod
    async def save(self, key: str, data: bytes) -> str:
        """Persist ``data`` under ``key``; return a storage URI."""

    @abstractmethod
    async def load(self, key: str) -> bytes:
        """Read the blob stored at ``key``."""

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Whether a blob exists at ``key``."""

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Remove the blob at ``key`` (idempotent)."""

    @staticmethod
    def sample_key(sha256: str) -> str:
        """Sharded key for a sample by its hash (avoids huge flat dirs)."""
        return f"samples/{sha256[:2]}/{sha256[2:4]}/{sha256}.apk"

    @staticmethod
    def report_key(job_id: str, filename: str) -> str:
        """Sharded key for a rendered report artifact of a job.

        Keyed by job rather than by content hash: two runs of the same sample are
        different jobs and must keep their own reports, since the analysis (and
        therefore the score) can legitimately differ between them.
        """
        jid = str(job_id)
        return f"reports/{jid[:2]}/{jid}/{filename}"
