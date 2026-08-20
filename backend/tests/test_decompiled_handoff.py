"""The storage-backed static → code-intel handoff.

Before this existed, the tree reached code intel as a filesystem *path*, so it only
arrived when both stages happened to run on the same worker. On a multi-worker
deployment the call-graph and control-flow analyzers degraded on every job and nothing
said so. (They degraded everywhere, in fact — the lookup read the wrong evidence key;
see ``test_static_task.TestDecompiledTree``.)

The rule these tests encode: the handoff is an optimisation, so every failure mode
degrades to "code intel runs without the tree" rather than failing a stage that already
produced a good envelope. The one exception is extraction safety, which is not
negotiable — the archive holds source decompiled from malware.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from typing import Any

import pytest

from app.services import artifacts
from app.storage.base import StorageBackend
from app.storage.local import LocalStorage

JOB_ID = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> LocalStorage:
    """A real storage backend on a temp dir, installed for the module under test."""
    store = LocalStorage(tmp_path / "storage")
    monkeypatch.setattr(artifacts, "get_storage", lambda: store)
    return store


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A small decompiled-source tree, shaped like JADX output."""
    root = tmp_path / "jadx"
    (root / "sources" / "com" / "evil").mkdir(parents=True)
    (root / "sources" / "com" / "evil" / "Payload.java").write_text("class Payload {}\n")
    (root / "sources" / "com" / "evil" / "Overlay.java").write_text("class Overlay {}\n")
    (root / "resources").mkdir()
    return root


def _files_under(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


class TestKeys:
    def test_the_archive_key_is_scoped_to_the_job(self) -> None:
        assert artifacts.archive_key(JOB_ID) == StorageBackend.artifact_key(
            JOB_ID, artifacts.ARCHIVE_NAME
        )

    def test_two_jobs_do_not_share_an_archive(self) -> None:
        # Re-analysing the same sample is a separate job, and one job's cleanup must
        # not delete another's tree out from under it.
        other = "99999999-2222-3333-4444-555555555555"

        assert artifacts.archive_key(JOB_ID) != artifacts.archive_key(other)


# ---------------------------------------------------------------------------
# Publish
# ---------------------------------------------------------------------------


class TestPublish:
    async def test_a_tree_is_archived_and_the_key_returned(
        self, storage: LocalStorage, tree: Path
    ) -> None:
        key = await artifacts.publish_tree(JOB_ID, tree)

        assert key == artifacts.archive_key(JOB_ID)
        assert await storage.exists(key)

    async def test_the_archive_holds_the_trees_contents(
        self, storage: LocalStorage, tree: Path
    ) -> None:
        key = await artifacts.publish_tree(JOB_ID, tree)

        with tarfile.open(fileobj=io.BytesIO(await storage.load(key)), mode="r:gz") as tar:
            names = {n.lstrip("./") for n in tar.getnames()}

        assert "sources/com/evil/Payload.java" in names

    async def test_the_archive_is_rooted_at_the_tree_not_the_workers_path(
        self, storage: LocalStorage, tree: Path
    ) -> None:
        # Otherwise extraction would nest a directory named after whichever worker's
        # temp path produced it, and the consumer's paths would not line up.
        key = await artifacts.publish_tree(JOB_ID, tree)

        with tarfile.open(fileobj=io.BytesIO(await storage.load(key)), mode="r:gz") as tar:
            assert not any(n.lstrip("./").startswith("jadx") for n in tar.getnames())

    async def test_a_missing_tree_publishes_nothing(
        self, storage: LocalStorage, tmp_path: Path
    ) -> None:
        # Static runs without JADX on PATH in plenty of deployments, so no tree at all
        # is an ordinary outcome rather than an error.
        assert await artifacts.publish_tree(JOB_ID, tmp_path / "never-existed") is None

    async def test_a_file_where_a_tree_was_expected_publishes_nothing(
        self, storage: LocalStorage, tmp_path: Path
    ) -> None:
        path = tmp_path / "not-a-dir"
        path.write_text("x")

        assert await artifacts.publish_tree(JOB_ID, path) is None

    async def test_an_empty_tree_is_still_published(
        self, storage: LocalStorage, tmp_path: Path
    ) -> None:
        # An empty directory means JADX ran and produced nothing, which is different
        # from JADX not running — the consumer can tell the two apart.
        empty = tmp_path / "empty"
        empty.mkdir()

        assert await artifacts.publish_tree(JOB_ID, empty) is not None

    async def test_a_republish_overwrites_rather_than_accumulating(
        self, storage: LocalStorage, tree: Path
    ) -> None:
        # A Celery retry re-runs the stage; two archives for one job would leak.
        first = await artifacts.publish_tree(JOB_ID, tree)
        (tree / "sources" / "extra.java").write_text("class Extra {}\n")
        second = await artifacts.publish_tree(JOB_ID, tree)

        assert first == second


class TestPublishDegradation:
    async def test_a_tree_over_the_cap_is_skipped_not_failed(
        self, storage: LocalStorage, tree: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # One pathological sample must not fill the bucket, and it must not fail a
        # stage whose envelope is perfectly good either.
        monkeypatch.setattr(artifacts.settings, "max_decompiled_archive_bytes", 1)

        key = await artifacts.publish_tree(JOB_ID, tree)

        assert key is None
        assert not await storage.exists(artifacts.archive_key(JOB_ID))

    async def test_an_unreachable_bucket_is_skipped_not_raised(
        self, tree: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class BrokenStorage:
            async def save(self, key: str, data: bytes) -> str:
                raise OSError("bucket unreachable")

        monkeypatch.setattr(artifacts, "get_storage", lambda: BrokenStorage())

        assert await artifacts.publish_tree(JOB_ID, tree) is None

    async def test_an_unpackable_tree_is_skipped_not_raised(
        self, storage: LocalStorage, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tree = tmp_path / "jadx"
        tree.mkdir()
        monkeypatch.setattr(
            artifacts.tarfile, "open", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full"))
        )

        assert await artifacts.publish_tree(JOB_ID, tree) is None


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


class TestFetch:
    async def test_a_published_tree_round_trips(
        self, storage: LocalStorage, tree: Path, tmp_path: Path
    ) -> None:
        # The whole point: what static wrote is what code intel reads, on a different
        # worker with a different filesystem.
        key = await artifacts.publish_tree(JOB_ID, tree)
        workspace = tmp_path / "other-worker"

        fetched = await artifacts.fetch_tree(JOB_ID, key or "", workspace)

        assert fetched is not None
        assert _files_under(fetched) == _files_under(tree)

    async def test_file_contents_survive(
        self, storage: LocalStorage, tree: Path, tmp_path: Path
    ) -> None:
        key = await artifacts.publish_tree(JOB_ID, tree)

        fetched = await artifacts.fetch_tree(JOB_ID, key or "", tmp_path / "ws")

        assert fetched is not None
        assert (fetched / "sources" / "com" / "evil" / "Payload.java").read_text() == (
            "class Payload {}\n"
        )

    async def test_it_extracts_under_the_job_workspace(
        self, storage: LocalStorage, tree: Path, tmp_path: Path
    ) -> None:
        key = await artifacts.publish_tree(JOB_ID, tree)
        workspace = tmp_path / "ws"

        fetched = await artifacts.fetch_tree(JOB_ID, key or "", workspace)

        assert fetched == workspace / artifacts.EXTRACT_DIRNAME

    async def test_an_absent_archive_degrades_to_none(
        self, storage: LocalStorage, tmp_path: Path
    ) -> None:
        # Static may have skipped publishing — no tree, or over the cap.
        assert await artifacts.fetch_tree(JOB_ID, "artifacts/no/such/key", tmp_path) is None

    async def test_a_previous_partial_extraction_is_cleared_first(
        self, storage: LocalStorage, tree: Path, tmp_path: Path
    ) -> None:
        # A retry must not merge into leftovers, or the analyzers read files that were
        # never in this sample.
        key = await artifacts.publish_tree(JOB_ID, tree)
        workspace = tmp_path / "ws"
        stale = workspace / artifacts.EXTRACT_DIRNAME / "sources"
        stale.mkdir(parents=True)
        (stale / "FromAnotherRun.java").write_text("class Stale {}\n")

        fetched = await artifacts.fetch_tree(JOB_ID, key or "", workspace)

        assert fetched is not None
        assert "sources/FromAnotherRun.java" not in _files_under(fetched)

    async def test_a_corrupt_archive_degrades_to_none(
        self, storage: LocalStorage, tmp_path: Path
    ) -> None:
        key = artifacts.archive_key(JOB_ID)
        await storage.save(key, b"this is not a gzip stream")

        assert await artifacts.fetch_tree(JOB_ID, key, tmp_path / "ws") is None

    async def test_an_unreachable_bucket_degrades_to_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class BrokenStorage:
            async def load(self, key: str) -> bytes:
                raise OSError("bucket unreachable")

        monkeypatch.setattr(artifacts, "get_storage", lambda: BrokenStorage())

        assert await artifacts.fetch_tree(JOB_ID, "k", tmp_path) is None


class TestExtractionSafety:
    """The archive is built from source decompiled out of a malware sample.

    Its member names are attacker-adjacent input, so extraction is filtered. This is
    the one part of the handoff that must not merely degrade.
    """

    async def _publish_raw(self, storage: LocalStorage, build) -> str:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            build(tar)
        key = artifacts.archive_key(JOB_ID)
        await storage.save(key, buffer.getvalue())
        return key

    async def test_a_parent_traversal_entry_cannot_escape_the_workspace(
        self, storage: LocalStorage, tmp_path: Path
    ) -> None:
        def build(tar: tarfile.TarFile) -> None:
            payload = b"owned"
            info = tarfile.TarInfo("../../escaped.txt")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))

        key = await self._publish_raw(storage, build)
        workspace = tmp_path / "ws"
        workspace.mkdir()

        await artifacts.fetch_tree(JOB_ID, key, workspace)

        assert not (tmp_path / "escaped.txt").exists()
        assert not (tmp_path.parent / "escaped.txt").exists()

    async def test_an_absolute_path_entry_cannot_escape(
        self, storage: LocalStorage, tmp_path: Path
    ) -> None:
        target = tmp_path / "absolute-target.txt"

        def build(tar: tarfile.TarFile) -> None:
            payload = b"owned"
            info = tarfile.TarInfo(f"/{target.relative_to(target.anchor)}")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))

        key = await self._publish_raw(storage, build)

        await artifacts.fetch_tree(JOB_ID, key, tmp_path / "ws")

        assert not target.exists()

    async def test_a_symlink_pointing_outside_is_not_created(
        self, storage: LocalStorage, tmp_path: Path
    ) -> None:
        secret = tmp_path / "secret.txt"
        secret.write_text("credentials")

        def build(tar: tarfile.TarFile) -> None:
            info = tarfile.TarInfo("link.txt")
            info.type = tarfile.SYMTYPE
            info.linkname = str(secret)
            tar.addfile(info)

        key = await self._publish_raw(storage, build)
        workspace = tmp_path / "ws"

        await artifacts.fetch_tree(JOB_ID, key, workspace)

        link = workspace / artifacts.EXTRACT_DIRNAME / "link.txt"
        assert not link.is_symlink()

    async def test_a_setuid_bit_is_not_preserved(
        self, storage: LocalStorage, tmp_path: Path
    ) -> None:
        def build(tar: tarfile.TarFile) -> None:
            payload = b"#!/bin/sh\n"
            info = tarfile.TarInfo("sources/tool.sh")
            info.size = len(payload)
            info.mode = 0o4755
            tar.addfile(info, io.BytesIO(payload))

        key = await self._publish_raw(storage, build)
        workspace = tmp_path / "ws"

        fetched = await artifacts.fetch_tree(JOB_ID, key, workspace)

        assert fetched is not None
        assert not (fetched / "sources" / "tool.sh").stat().st_mode & 0o4000

    async def test_a_hostile_archive_leaves_nothing_half_extracted(
        self, storage: LocalStorage, tmp_path: Path
    ) -> None:
        # A rejected archive must not leave a directory that looks like a usable tree,
        # or the analyzers would report on a fragment as though it were the sample.
        def build(tar: tarfile.TarFile) -> None:
            good = b"class Ok {}\n"
            info = tarfile.TarInfo("sources/Ok.java")
            info.size = len(good)
            tar.addfile(info, io.BytesIO(good))
            bad = tarfile.TarInfo("../../escaped.txt")
            bad.size = 0
            tar.addfile(bad, io.BytesIO(b""))

        key = await self._publish_raw(storage, build)
        workspace = tmp_path / "ws"

        result = await artifacts.fetch_tree(JOB_ID, key, workspace)

        assert result is None
        assert not (workspace / artifacts.EXTRACT_DIRNAME).exists()


# ---------------------------------------------------------------------------
# Discard
# ---------------------------------------------------------------------------


class TestDiscard:
    async def test_the_archive_is_deleted(self, storage: LocalStorage, tree: Path) -> None:
        # It is derived from a malware sample, so it does not outlive the analysis —
        # the same rule the local workspace follows.
        key = await artifacts.publish_tree(JOB_ID, tree)
        assert key is not None

        await artifacts.discard_tree(JOB_ID, key)

        assert not await storage.exists(key)

    async def test_discarding_an_absent_archive_is_not_an_error(
        self, storage: LocalStorage
    ) -> None:
        # Cleanup runs in a `finally` whether or not anything was published.
        await artifacts.discard_tree(JOB_ID, artifacts.archive_key(JOB_ID))

    async def test_a_delete_failure_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # It runs in the cleanup path of a completed stage: a leaked object is a
        # storage-lifecycle problem, not a reason to report the stage as failed.
        class BrokenStorage:
            async def delete(self, key: str) -> None:
                raise OSError("bucket unreachable")

        monkeypatch.setattr(artifacts, "get_storage", lambda: BrokenStorage())

        await artifacts.discard_tree(JOB_ID, "k")


# ---------------------------------------------------------------------------
# Resolution order in the code-intel stage
# ---------------------------------------------------------------------------


class TestResolution:
    def _payload(self, **decompile: Any) -> dict[str, Any]:
        return {"evidence": {"decompiled_java": decompile}}

    async def test_a_local_tree_is_preferred_over_the_archive(
        self, storage: LocalStorage, tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Downloading a copy of what is already unpacked on this disk is pure waste.
        from app.tasks import code_intel as ci

        key = await artifacts.publish_tree(JOB_ID, tree)
        fetched: list[str] = []
        monkeypatch.setattr(ci, "fetch_tree", lambda *a, **k: fetched.append("called") or None)

        resolved = await ci.resolve_decompiled_tree(
            self._payload(artifact_dir=str(tree), artifact_archive_key=key),
            job_id=JOB_ID,
            workspace=tmp_path / "ws",
        )

        assert resolved == tree
        assert fetched == []

    async def test_the_archive_is_used_when_the_local_tree_is_gone(
        self, storage: LocalStorage, tree: Path, tmp_path: Path
    ) -> None:
        # The multi-worker case this whole module exists for.
        from app.tasks import code_intel as ci

        key = await artifacts.publish_tree(JOB_ID, tree)
        payload = self._payload(
            artifact_dir=str(tmp_path / "another-workers-path"), artifact_archive_key=key
        )

        resolved = await ci.resolve_decompiled_tree(
            payload, job_id=JOB_ID, workspace=tmp_path / "ws"
        )

        assert resolved is not None
        assert _files_under(resolved) == _files_under(tree)

    async def test_no_local_tree_and_no_archive_resolves_to_none(self, tmp_path: Path) -> None:
        from app.tasks import code_intel as ci

        resolved = await ci.resolve_decompiled_tree(
            self._payload(), job_id=JOB_ID, workspace=tmp_path
        )

        assert resolved is None

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"evidence": None},
            {"evidence": {}},
            {"evidence": {"decompiled_java": None}},
            {"evidence": {"decompiled_java": {}}},
            {"evidence": {"decompiled_java": {"artifact_archive_key": ""}}},
            {"evidence": {"decompiled_java": {"artifact_archive_key": 42}}},
        ],
    )
    async def test_malformed_evidence_resolves_to_none(
        self, payload: dict[str, Any], tmp_path: Path
    ) -> None:
        # Evidence comes from a process that parsed a malware sample; it is untrusted
        # input and must never raise here.
        from app.tasks import code_intel as ci

        assert await ci.resolve_decompiled_tree(payload, job_id=JOB_ID, workspace=tmp_path) is None


# ---------------------------------------------------------------------------
# Publication from the static stage
# ---------------------------------------------------------------------------


class TestStaticStagePublishes:
    """The static task is what records the key, not the engine.

    Engines must not know that object storage exists — ``backend/.importlinter``
    enforces that boundary — so the engine reports a local path and the task is what
    makes it reachable from another worker.
    """

    async def _publish(self, payload: dict[str, Any]) -> dict[str, Any]:
        from app.tasks import static as st

        await st._publish_decompiled_tree(payload, job_id=JOB_ID)
        return payload

    async def test_the_archive_key_is_recorded_beside_the_path(
        self, storage: LocalStorage, tree: Path
    ) -> None:
        payload = await self._publish(
            {"evidence": {"decompiled_java": {"artifact_dir": str(tree)}}}
        )

        decompile = payload["evidence"]["decompiled_java"]
        assert decompile["artifact_archive_key"] == artifacts.archive_key(JOB_ID)
        # The path stays: it is the fast path when the next stage lands on this worker.
        assert decompile["artifact_dir"] == str(tree)

    async def test_nothing_is_recorded_when_the_tree_is_absent(
        self, storage: LocalStorage, tmp_path: Path
    ) -> None:
        payload = await self._publish(
            {"evidence": {"decompiled_java": {"artifact_dir": str(tmp_path / "gone")}}}
        )

        assert "artifact_archive_key" not in payload["evidence"]["decompiled_java"]

    async def test_nothing_is_recorded_when_the_tree_exceeds_the_cap(
        self, storage: LocalStorage, tree: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(artifacts.settings, "max_decompiled_archive_bytes", 1)

        payload = await self._publish(
            {"evidence": {"decompiled_java": {"artifact_dir": str(tree)}}}
        )

        assert "artifact_archive_key" not in payload["evidence"]["decompiled_java"]

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"evidence": None},
            {"evidence": {}},
            {"evidence": {"decompiled_java": None}},
            {"evidence": {"decompiled_java": {}}},
            {"evidence": {"decompiled_java": {"artifact_dir": ""}}},
            {"evidence": {"decompiled_java": {"artifact_dir": 42}}},
        ],
    )
    async def test_a_malformed_envelope_is_left_alone(
        self, storage: LocalStorage, payload: dict[str, Any]
    ) -> None:
        # The envelope is produced by a process that parsed a malware sample. Raising
        # here would lose an envelope that is otherwise complete.
        before = repr(payload)

        await self._publish(payload)

        assert repr(payload) == before

    async def test_a_full_round_trip_across_two_workers(
        self, storage: LocalStorage, tree: Path, tmp_path: Path
    ) -> None:
        # End to end: static publishes on worker A, the local path does not exist on
        # worker B, and code intel still gets the tree.
        from app.tasks import code_intel as ci

        payload = await self._publish(
            {"evidence": {"decompiled_java": {"artifact_dir": str(tree)}}}
        )
        # Worker B cannot see worker A's disk.
        import shutil

        shutil.rmtree(tree)

        resolved = await ci.resolve_decompiled_tree(
            payload, job_id=JOB_ID, workspace=tmp_path / "worker-b"
        )

        assert resolved is not None
        assert (resolved / "sources" / "com" / "evil" / "Payload.java").exists()
