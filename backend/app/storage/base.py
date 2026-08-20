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

    def uri_for(self, key: str) -> str:
        """The URI ``save`` would return for ``key``, without writing anything.

        Needed because a caller that skips the upload — the sample is already stored,
        so its bytes are content-identical — still has to record where the bytes are.
        Building that string at the call site hardcoded ``file://`` and so lied about
        every S3 deployment.
        """
        raise NotImplementedError

    @staticmethod
    def sample_key(sha256: str) -> str:
        """Sharded key for a sample by its hash (avoids huge flat dirs)."""
        return f"samples/{sha256[:2]}/{sha256[2:4]}/{sha256}.apk"

    @staticmethod
    def artifact_key(job_id: str, name: str) -> str:
        """Sharded key for an intermediate artifact one stage hands to another.

        Keyed by job, like reports and unlike samples: the artifact belongs to a
        single analysis run, and it is deleted when the last stage that needs it is
        done rather than retained.
        """
        jid = str(job_id)
        return f"artifacts/{jid[:2]}/{jid}/{name}"

    @staticmethod
    def report_key(job_id: str, filename: str) -> str:
        """Sharded key for a rendered report artifact of a job.

        Keyed by job rather than by content hash: two runs of the same sample are
        different jobs and must keep their own reports, since the analysis (and
        therefore the score) can legitimately differ between them.
        """
        jid = str(job_id)
        return f"reports/{jid[:2]}/{jid}/{filename}"
