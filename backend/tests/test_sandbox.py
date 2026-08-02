"""Tests for the sandbox runner adapters.

The sandbox is the one component that executes malware, so the tests focus on
the safety-relevant behaviour: disabled by default, argv built as a list (never
a shell string), timeouts enforced, and a run that produces no artifacts treated
as a failure rather than an empty success.

No emulator is involved — the subprocess is a stub script.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.sandbox import (
    ARTIFACT_FILES,
    DisabledSandboxRunner,
    SandboxDisabledError,
    SandboxError,
    SandboxTimeoutError,
    SubprocessSandboxRunner,
    get_sandbox_runner,
)


def _runner(tmp_path: Path, mode: str = "compose", timeout: int = 5) -> SubprocessSandboxRunner:
    return SubprocessSandboxRunner(
        mode=mode,
        sandbox_dir=tmp_path,
        compose_file=tmp_path / "docker-compose.sandbox.yml",
        timeout_secs=timeout,
        api_level=33,
    )


# ---------------------------------------------------------------------------
# Policy gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disabled_runner_refuses(tmp_path: Path) -> None:
    with pytest.raises(SandboxDisabledError, match="disabled"):
        await DisabledSandboxRunner().run(tmp_path / "a.apk", tmp_path / "out", job_id="j1")


def test_default_configuration_is_disabled() -> None:
    """Dynamic analysis must never switch itself on implicitly."""
    runner = get_sandbox_runner()
    assert isinstance(runner, DisabledSandboxRunner)
    assert runner.available is False
    assert "SEPHELA_DYNAMIC_ENABLED" in runner.unavailable_reason()


def test_real_runner_reports_available(tmp_path: Path) -> None:
    assert _runner(tmp_path).available is True


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------


def test_compose_argv_uses_container_paths(tmp_path: Path) -> None:
    argv = _runner(tmp_path).build_argv(tmp_path / "in" / "abc.apk", tmp_path / "out")

    assert argv[:4] == ["docker", "compose", "-f", str(tmp_path / "docker-compose.sandbox.yml")]
    assert "--rm" in argv and "sandbox" in argv
    # Container-side paths, per the compose bind mounts.
    assert "/samples/abc.apk" in argv
    assert "/output" in argv
    assert argv[argv.index("--timeout") + 1] == "5"
    assert argv[argv.index("--api-level") + 1] == "33"


def test_script_argv_uses_host_paths(tmp_path: Path) -> None:
    apk = tmp_path / "in" / "abc.apk"
    out = tmp_path / "out"
    argv = _runner(tmp_path, mode="script").build_argv(apk, out)

    assert argv[0] == str(tmp_path / "run_analysis.sh")
    assert argv[1] == str(apk)
    assert argv[2] == str(out)


def test_unknown_mode_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(SandboxError, match="Unknown sandbox runner mode"):
        _runner(tmp_path, mode="wat").build_argv(tmp_path / "a.apk", tmp_path / "out")


def test_argv_is_a_list_so_filenames_cannot_inject(tmp_path: Path) -> None:
    """A hostile APK filename must land as one argv element, not shell syntax.

    Because argv is a list and the runner never uses shell=True, metacharacters
    are inert data. If this ever became a shell string, the `;` would execute.
    """
    hostile = tmp_path / "in" / "x; rm -rf tmp.apk"
    argv = _runner(tmp_path).build_argv(hostile, tmp_path / "out")

    assert "/samples/x; rm -rf tmp.apk" in argv  # one element, semicolon included
    assert all(isinstance(a, str) for a in argv)


def test_env_exposes_bind_mount_sources(tmp_path: Path) -> None:
    apk = tmp_path / "in" / "abc.apk"
    out = tmp_path / "out"
    out.mkdir()
    (tmp_path / "in").mkdir()

    env = _runner(tmp_path).build_env(apk, out)
    assert env["SEPHELA_SAMPLES_DIR"] == str((tmp_path / "in").resolve())
    assert env["SEPHELA_OUTPUT_DIR"] == str(out.resolve())


# ---------------------------------------------------------------------------
# Subprocess execution — with a stub "sandbox"
# ---------------------------------------------------------------------------


class _StubRunner(SubprocessSandboxRunner):
    """Replaces the real command with a shell stub, keeping run() under test."""

    def __init__(self, script: str, tmp_path: Path, timeout: int = 5) -> None:
        super().__init__(
            mode="script",
            sandbox_dir=tmp_path,
            compose_file=tmp_path / "nope.yml",
            timeout_secs=timeout,
            api_level=33,
        )
        self._script = script

    def build_argv(self, apk_path: Path, output_dir: Path) -> list[str]:
        # Plain replace, not str.format — stub scripts may contain JSON braces.
        return ["/bin/sh", "-c", self._script.replace("{out}", str(output_dir))]


@pytest.mark.asyncio
async def test_successful_run_returns_artifacts_dir(tmp_path: Path) -> None:
    out = tmp_path / "out"
    meta = json.dumps({"sandbox_id": "s1", "apk_sha256": "ab" * 32})
    runner = _StubRunner(f"echo '{meta}' > {{out}}/metadata.json", tmp_path)

    result = await runner.run(tmp_path / "a.apk", out, job_id="j1")

    assert result == out
    assert (out / "metadata.json").is_file()


@pytest.mark.asyncio
async def test_nonzero_exit_raises_with_output_tail(tmp_path: Path) -> None:
    runner = _StubRunner("echo 'emulator failed to boot' >&2; exit 3", tmp_path)
    with pytest.raises(SandboxError, match="exited 3") as exc:
        await runner.run(tmp_path / "a.apk", tmp_path / "out", job_id="j1")
    assert "emulator failed to boot" in str(exc.value)


@pytest.mark.asyncio
async def test_zero_exit_without_artifacts_is_a_failure(tmp_path: Path) -> None:
    """A silent no-op sandbox must not look like a clean run with no findings."""
    runner = _StubRunner("exit 0", tmp_path)
    with pytest.raises(SandboxError, match="no artifacts"):
        await runner.run(tmp_path / "a.apk", tmp_path / "out", job_id="j1")


@pytest.mark.asyncio
async def test_timeout_kills_the_sandbox(tmp_path: Path, monkeypatch) -> None:
    from app.core import config

    # Collapse the grace budget so the test is fast.
    monkeypatch.setattr(config.settings, "sandbox_timeout_grace_secs", 0, raising=False)
    runner = _StubRunner("sleep 30", tmp_path, timeout=1)

    with pytest.raises(SandboxTimeoutError, match="wall-clock budget"):
        await runner.run(tmp_path / "a.apk", tmp_path / "out", job_id="j1")


@pytest.mark.asyncio
async def test_missing_executable_is_reported_clearly(tmp_path: Path) -> None:
    runner = _runner(tmp_path, mode="script")  # run_analysis.sh does not exist here
    with pytest.raises(SandboxError, match="executable not found"):
        await runner.run(tmp_path / "a.apk", tmp_path / "out", job_id="j1")


def test_artifact_file_list_matches_the_engine_contract() -> None:
    """The engine reads these four names; keep the lists in lockstep."""
    assert set(ARTIFACT_FILES) == {
        "metadata.json",
        "frida_trace.json",
        "network.json",
        "logcat.json",
    }
