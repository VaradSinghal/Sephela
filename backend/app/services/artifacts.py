"""Stage-to-stage artifact handoff through object storage.

The static stage decompiles an APK into a JADX source tree and code intel reads that
tree for its call-graph and control-flow analyzers. Until now the handoff was a
filesystem *path* recorded in the static envelope, which works only when both stages
run on the same worker. On a multi-worker deployment they routinely do not, code intel
found nothing at the path, and passed ``None`` — costing analysis depth silently.

This module moves the tree through the same storage the samples and reports use, so
the handoff no longer depends on scheduling.

Degradation is deliberate throughout. The tree is an *optimisation*: the code-intel
engine treats it as optional and produces a correct envelope without it. So every
failure here — an oversized tree, an unreachable bucket, a corrupt archive — is logged
and skipped rather than raised. Failing the stage would trade a real result for none.
"""

from __future__ import annotations

import asyncio
import shutil
import tarfile
import tempfile
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger
from app.storage import get_storage
from app.storage.base import StorageBackend

logger = get_logger(__name__)

#: Name of the archive within the job's artifact prefix. One per job, so a retry
#: overwrites rather than accumulating.
ARCHIVE_NAME = "decompiled.tar.gz"

#: Where ``fetch_tree`` extracts into, under the job workspace.
EXTRACT_DIRNAME = "decompiled"


def archive_key(job_id: str) -> str:
    """Storage key for a job's decompiled-source archive."""
    return StorageBackend.artifact_key(job_id, ARCHIVE_NAME)


async def publish_tree(job_id: str, tree: Path) -> str | None:
    """Archive ``tree`` into storage and return its key, or None if it was skipped.

    Returns None — never raises — when there is nothing to publish or publishing is
    not worth it, because the consumer degrades gracefully and a failed handoff must
    not fail the stage that produced a perfectly good envelope.
    """
    if not tree.is_dir():
        return None

    def _pack() -> tuple[Path, int]:
        # To a temp file rather than memory: a decompiled tree is hundreds of
        # megabytes of source and holding it twice over is avoidable.
        handle = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
        handle.close()
        path = Path(handle.name)
        with tarfile.open(path, "w:gz") as archive:
            # arcname="." keeps the archive rooted at the tree itself, so extracting
            # it reproduces the tree's contents rather than nesting a directory named
            # after whichever worker's path it happened to come from.
            archive.add(tree, arcname=".")
        return path, path.stat().st_size

    try:
        archive_path, size = await asyncio.to_thread(_pack)
    except OSError as exc:
        logger.warning("decompiled_archive_pack_failed", job_id=job_id, error=str(exc))
        return None

    try:
        cap = settings.max_decompiled_archive_bytes
        if size > cap:
            logger.warning(
                "decompiled_archive_too_large",
                job_id=job_id,
                size_bytes=size,
                cap_bytes=cap,
                detail="code intel will run without the decompiled tree",
            )
            return None

        key = archive_key(job_id)
        try:
            data = await asyncio.to_thread(archive_path.read_bytes)
            await get_storage().save(key, data)
        except Exception as exc:  # noqa: BLE001 — see the module docstring
            logger.warning("decompiled_archive_upload_failed", job_id=job_id, error=str(exc))
            return None

        logger.info("decompiled_archive_published", job_id=job_id, key=key, size_bytes=size)
        return key
    finally:
        await asyncio.to_thread(archive_path.unlink, True)


async def fetch_tree(job_id: str, key: str, workspace: Path) -> Path | None:
    """Download and extract the archive at ``key``; return the tree, or None.

    Extraction uses ``filter="data"``, which is not optional here. The archive holds
    source decompiled from a malware sample, so its member names are attacker-adjacent
    input: the filter rejects absolute paths, ``..`` traversal, links pointing outside
    the destination, device nodes, and setuid bits. Without it a crafted entry could
    write anywhere the worker can.
    """
    try:
        data = await get_storage().load(key)
    except FileNotFoundError:
        logger.info("decompiled_archive_absent", job_id=job_id, key=key)
        return None
    except Exception as exc:  # noqa: BLE001 — see the module docstring
        logger.warning("decompiled_archive_download_failed", job_id=job_id, error=str(exc))
        return None

    destination = workspace / EXTRACT_DIRNAME

    def _unpack() -> Path | None:
        # A previous attempt's partial extraction would otherwise be merged into.
        shutil.rmtree(destination, ignore_errors=True)
        destination.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
        try:
            handle.write(data)
            handle.close()
            with tarfile.open(handle.name, "r:gz") as archive:
                archive.extractall(path=destination, filter="data")
        finally:
            Path(handle.name).unlink(missing_ok=True)
        return destination

    try:
        tree = await asyncio.to_thread(_unpack)
    except (OSError, tarfile.TarError, ValueError) as exc:
        # tarfile raises ValueError-family errors for members the filter rejects, so a
        # hostile archive lands here rather than escaping the workspace.
        logger.warning("decompiled_archive_extract_failed", job_id=job_id, error=str(exc))
        shutil.rmtree(destination, ignore_errors=True)
        return None

    logger.info("decompiled_archive_fetched", job_id=job_id, key=key, path=str(tree))
    return tree


async def discard_tree(job_id: str, key: str) -> None:
    """Delete the archive. Called by the last stage that needs it.

    The tree is derived from a malware sample, so it does not outlive the analysis —
    the same rule the local workspace follows. Never raises: a leaked object is a
    storage-lifecycle problem, not a reason to fail a completed stage.
    """
    try:
        await get_storage().delete(key)
        logger.info("decompiled_archive_discarded", job_id=job_id, key=key)
    except Exception as exc:  # noqa: BLE001 — see the module docstring
        logger.warning("decompiled_archive_delete_failed", job_id=job_id, key=key, error=str(exc))
