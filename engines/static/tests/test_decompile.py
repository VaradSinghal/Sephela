"""Smali and JADX decompilation extractors.

Both are tool-dependent and both are routinely absent — JADX is a Java CLI rather
than a pip dependency. The contract is that their absence is a recorded partial
failure, never a crash, and that their evidence stays bounded when they do run: the
envelope is stored as a database row and read into an LLM prompt.

These therefore prove the *degradation* contract, not that decompilation works.
Exercising the latter needs the engine image, with JADX and androguard installed.
"""

from __future__ import annotations

import shutil

import pytest
from conftest import FakeApk  # type: ignore[import-not-found]

from sephela_static.extractors.decompile import DecompileExtractor, SmaliExtractor


class FakeMethod:
    pass


class FakeClass:
    def __init__(self, name: str, method_count: int = 2) -> None:
        self._name = name
        self._methods = [FakeMethod() for _ in range(method_count)]

    def get_name(self) -> str:
        return self._name

    def get_methods(self) -> list[FakeMethod]:
        return list(self._methods)


class FakeDex:
    """Stands in for ``androguard.core.dex.DEX``."""

    registry: dict[bytes, list[FakeClass]] = {}

    def __init__(self, blob: bytes) -> None:
        self._classes = self.registry.get(blob, [])

    def get_classes(self) -> list[FakeClass]:
        return list(self._classes)


@pytest.fixture
def fake_dex(monkeypatch: pytest.MonkeyPatch):
    """Install a fake ``androguard.core.dex`` so SmaliExtractor runs without it.

    The extractor imports the module inside ``extract``, so the module has to exist in
    ``sys.modules`` before the call.
    """
    import sys
    import types

    module = types.ModuleType("androguard.core.dex")
    module.DEX = FakeDex  # type: ignore[attr-defined]
    core = types.ModuleType("androguard.core")
    core.dex = module  # type: ignore[attr-defined]
    root = types.ModuleType("androguard")
    root.core = core  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "androguard", root)
    monkeypatch.setitem(sys.modules, "androguard.core", core)
    monkeypatch.setitem(sys.modules, "androguard.core.dex", module)

    def _register(blobs: dict[bytes, list[FakeClass]]) -> None:
        FakeDex.registry = blobs

    yield _register
    FakeDex.registry = {}


class TestSmaliExtractor:
    def test_classes_and_methods_are_counted(self, make_context, fake_dex) -> None:
        fake_dex({b"dex-1": [FakeClass("Lcom/example/A;", 3), FakeClass("Lcom/example/B;", 2)]})
        ctx = make_context(apk=FakeApk(dexes=[b"dex-1"]))

        evidence = SmaliExtractor().extract(ctx).evidence

        assert evidence["class_count"] == 2
        assert evidence["method_count"] == 5

    def test_every_dex_in_a_multidex_apk_is_read(self, make_context, fake_dex) -> None:
        # Above the 64k method limit an app is multidex, and malware often puts its
        # payload in the second file precisely because tools stop at the first.
        fake_dex({b"dex-1": [FakeClass("Lcom/a/A;")], b"dex-2": [FakeClass("Lcom/b/B;")]})
        ctx = make_context(apk=FakeApk(dexes=[b"dex-1", b"dex-2"]))

        evidence = SmaliExtractor().extract(ctx).evidence

        assert evidence["class_count"] == 2
        assert set(evidence["classes"]) == {"Lcom/a/A;", "Lcom/b/B;"}

    def test_the_class_list_is_capped_but_the_count_is_not(self, make_context, fake_dex) -> None:
        # The envelope is a database row and is read into a prompt; 200k class names
        # would blow both. The count is what preserves the scale.
        classes = [FakeClass(f"Lcom/example/C{i};") for i in range(5200)]
        fake_dex({b"dex-1": classes})
        ctx = make_context(apk=FakeApk(dexes=[b"dex-1"]))

        evidence = SmaliExtractor().extract(ctx).evidence

        assert evidence["class_count"] == 5200
        assert len(evidence["classes"]) == 5000

    def test_an_apk_with_no_dex_yields_zeroes(self, make_context, fake_dex) -> None:
        # A resources-only split APK is a real input.
        fake_dex({})
        ctx = make_context(apk=FakeApk(dexes=[]))

        evidence = SmaliExtractor().extract(ctx).evidence

        assert evidence["class_count"] == 0
        assert evidence["method_count"] == 0
        assert evidence["classes"] == []

    def test_it_raises_no_findings(self, make_context, fake_dex) -> None:
        # A class inventory is context. The obfuscation extractor is what turns it into
        # a judgement, from this same evidence.
        fake_dex({b"dex-1": [FakeClass("La/b;")]})
        ctx = make_context(apk=FakeApk(dexes=[b"dex-1"]))

        assert SmaliExtractor().extract(ctx).findings == []

    def test_its_output_is_what_the_obfuscation_extractor_reads(
        self, make_context, fake_dex
    ) -> None:
        # ObfuscationExtractor reads ctx.shared["smali"]["classes"], so the key name
        # here is a contract rather than an implementation detail.
        fake_dex({b"dex-1": [FakeClass("La/b;")]})
        ctx = make_context(apk=FakeApk(dexes=[b"dex-1"]))

        evidence = SmaliExtractor().extract(ctx).evidence

        assert "classes" in evidence
        assert SmaliExtractor.name == "smali"

    def test_it_declares_that_it_needs_tooling(self) -> None:
        assert SmaliExtractor.requires_tools is True

    def test_a_missing_androguard_propagates_for_the_pipeline_to_isolate(
        self, make_context, monkeypatch
    ) -> None:
        # It must raise rather than return empty evidence: an empty class list would
        # make the obfuscation extractor report a clean 0.0 ratio for a sample nobody
        # managed to parse.
        import sys

        monkeypatch.setitem(sys.modules, "androguard.core.dex", None)

        with pytest.raises(Exception):  # noqa: B017 — the import machinery's choice
            SmaliExtractor().extract(make_context(apk=FakeApk(dexes=[b"x"])))


class TestDecompileExtractor:
    def test_it_raises_a_clear_error_when_jadx_is_absent(self, make_context) -> None:
        # The case on any machine without the engine image, including CI. The pipeline
        # records it in `errors` and the run degrades to `partial`, so this message is
        # what an operator reads — it has to name the missing tool.
        if shutil.which("jadx") is not None:
            pytest.skip("jadx is on PATH; the absent-tool path cannot be exercised here")

        with pytest.raises(RuntimeError, match="JADX not found"):
            DecompileExtractor().extract(make_context())

    def test_the_error_says_where_to_fix_it(self, make_context) -> None:
        if shutil.which("jadx") is not None:
            pytest.skip("jadx is on PATH")

        with pytest.raises(RuntimeError, match="engine image"):
            DecompileExtractor().extract(make_context())

    def test_it_declares_that_it_needs_tooling(self) -> None:
        assert DecompileExtractor.requires_tools is True

    def test_the_workdir_defaults_to_beside_the_sample(self) -> None:
        # Left None, the tree lands next to the APK — which for the backend means inside
        # the per-job workspace it already cleans up.
        assert DecompileExtractor().workdir is None

    def test_a_workdir_can_be_supplied(self, tmp_path) -> None:
        extractor = DecompileExtractor(workdir=tmp_path)

        assert extractor.workdir == tmp_path

    def test_the_timeout_is_generous_enough_for_a_real_apk(self) -> None:
        # Decompiling a large APK is minutes. A short default would turn every big
        # sample into a partial run.
        assert DecompileExtractor().timeout >= 300

    def test_the_evidence_key_is_what_the_backend_looks_up(self) -> None:
        # app.tasks.code_intel resolves the tree from evidence["decompiled_java"]. It
        # read "decompile" for a while, and so found the tree on no deployment at all.
        assert DecompileExtractor.name == "decompiled_java"
