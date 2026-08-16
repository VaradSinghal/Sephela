"""Import-surface tests for the `ai` distribution.

A subpackage whose ``__init__`` is broken, or one missing from pyproject's package
list, is invisible to every other test: the suite only imports what it happens to
use, so a module nobody exercises can stay unimportable indefinitely (which is how
``ai.prompts`` came to re-export from paths that did not exist). These tests import
the whole public surface, and pin the package list the wheel ships.
"""

from __future__ import annotations

import importlib
import pkgutil
import tomllib
from pathlib import Path

import pytest

import ai

_AI_ROOT = Path(ai.__file__).parent
_PYPROJECT = _AI_ROOT / "pyproject.toml"


def _declared_packages() -> set[str]:
    with _PYPROJECT.open("rb") as fh:
        return set(tomllib.load(fh)["tool"]["setuptools"]["packages"])


def _source_packages() -> set[str]:
    """Every importable subpackage on disk, excluding the test suite itself."""
    found = {"ai"}
    for mod in pkgutil.walk_packages([str(_AI_ROOT)], prefix="ai."):
        if mod.ispkg and not mod.name.startswith("ai.tests"):
            found.add(mod.name)
    return found


class TestPackageDeclaration:
    def test_every_subpackage_on_disk_is_declared_for_distribution(self) -> None:
        # packages are listed explicitly (find() cannot express them from inside
        # ai/), so a new subpackage silently missing from the wheel is a real risk.
        missing = _source_packages() - _declared_packages()
        assert not missing, (
            f"add to ai/pyproject.toml [tool.setuptools].packages: {sorted(missing)}"
        )

    def test_no_declared_package_has_gone_missing(self) -> None:
        stale = _declared_packages() - _source_packages()
        assert not stale, f"declared but not on disk: {sorted(stale)}"

    def test_the_test_suite_is_not_shipped(self) -> None:
        assert not any(p.startswith("ai.tests") for p in _declared_packages())


@pytest.mark.parametrize("module", sorted(_source_packages()))
def test_every_subpackage_imports(module: str) -> None:
    importlib.import_module(module)


@pytest.mark.parametrize(
    "module",
    [
        "ai.integration",
        "ai.orchestration.runner",
        "ai.orchestration.workflow",
        "ai.prompts.prompt_manager",
        "ai.rag.service",
        "ai.scoring.engine",
    ],
)
def test_the_documented_entry_points_import(module: str) -> None:
    importlib.import_module(module)


class TestTopLevelExports:
    def test_the_public_api_is_reachable_from_the_package_root(self) -> None:
        for name in ai.__all__:
            assert hasattr(ai, name), f"ai.__all__ advertises {name} but it is absent"

    def test_the_prompt_helpers_are_re_exported(self) -> None:
        from ai.prompts import SYSTEM_PROMPTS, get_system_prompt

        assert SYSTEM_PROMPTS
        assert callable(get_system_prompt)
