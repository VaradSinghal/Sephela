"""Sample materialization — getting APK bytes out of storage and onto disk.

Engines take a filesystem path, not a blob key: they shell out to ``jadx`` and
``androguard``, which read files. This module is the one place that bridges the
two, so every stage that needs the sample on disk gets the same per-job layout
and the same failure mode when the bytes are gone.

Callers own cleanup. A directory here holds a live malware sample, so the stages
that create one remove it in a ``finally`` (see ``app.tasks.dynamic``).
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from app.core.config import settings
from app.db.models.analysis import Sample
from app.storage.base import StorageBackend
from app.storage.local import LocalStorage


def storage() -> StorageBackend:
    """Resolve the configured storage backend. Mirrors ``app.api.deps``."""
    # S3 lands with its phase; local is the only backend today.
    return LocalStorage(settings.storage_local_root)


def job_workspace_dir(job_id: uuid.UUID | str) -> Path:
    """Per-job scratch directory for engines that need files on disk.

    Deliberately separate from ``app.services.sandbox.job_artifacts_dir``: that
    root is bind-mounted into the malware sandbox and wiped on its own schedule,
    and the static → code-intel handoff must not depend on the sandbox's cleanup
    timing to survive.
    """
    return Path(settings.engine_workspace_root).resolve() / str(job_id)


async def materialize_apk(sample: Sample, dest_dir: Path) -> Path:
    """Copy the APK out of object storage into ``dest_dir``.

    The sample gets its own per-job directory rather than being read from the
    shared storage root, so a stage that bind-mounts its input directory (the
    sandbox) exposes exactly one file.

    Raises ``FileNotFoundError`` when the bytes are not in storage.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    apk_path = dest_dir / f"{sample.sha256}.apk"
    data = await storage().load(StorageBackend.sample_key(sample.sha256))
    await asyncio.to_thread(apk_path.write_bytes, data)
    return apk_path
