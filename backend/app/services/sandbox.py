"""Sandbox runner adapters — the orchestrator's seam to ``infra/sandbox/``.

The backend never executes malware itself. It asks a sandbox runner to produce
runtime *artifacts* (frida_trace.json, network.json, logcat.json, metadata.json),
then hands that directory to the dynamic engine, which only ever parses data.

Three modes, selected by ``settings.sandbox_runner``:

``disabled`` (default)
    Refuses to run. Dynamic analysis is policy-gated and expensive; it must be
    switched on deliberately, per docs/architecture/02-services.md.
``compose``
    ``docker compose -f infra/sandbox/docker-compose.sandbox.yml run --rm sandbox``
    — the documented path (infra/sandbox/README.md). Requires KVM on the host.
``script``
    Runs ``run_analysis.sh`` directly, for a worker already inside an
    emulator-capable image.

Security posture (docs/architecture/09-security.md):
- argv lists only — never ``shell=True``, so an APK filename can't inject a command.
- a hard wall-clock timeout; the process tree is killed on expiry.
- artifacts are validated to exist before the engine is invoked.
"""

from __future__ import annotations

import asyncio
import shutil
import uuid
from abc import ABC, abstractmethod
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Written by run_analysis.sh; the engine skips extractors whose file is absent,
# so a run is usable as long as at least one landed.
ARTIFACT_FILES = ("metadata.json", "frida_trace.json", "network.json", "logcat.json")

_DISABLED_MESSAGE = (
    "Dynamic analysis is disabled (set SEPHELA_DYNAMIC_ENABLED=true and "
    "SEPHELA_SANDBOX_RUNNER=compose on a KVM-capable host)."
)


class SandboxError(RuntimeError):
    """Sandbox could not produce artifacts."""


class SandboxDisabledError(SandboxError):
    """Dynamic analysis is switched off by policy."""


class SandboxTimeoutError(SandboxError):
    """The sandbox exceeded its wall-clock budget."""


class SandboxRunner(ABC):
    """Produces a directory of runtime artifacts for one APK."""

    #: False when the runner cannot do work at all, so callers can short-circuit
    #: before spending effort (e.g. copying an APK out of object storage).
    available: bool = True

    @abstractmethod
    async def run(self, apk_path: Path, output_dir: Path, *, job_id: str) -> Path:
        """Analyze ``apk_path``, writing artifacts into ``output_dir``.

        Returns the artifacts directory. Raises ``SandboxError`` on failure.
        """

    def unavailable_reason(self) -> str:
        """Why this runner cannot run; only meaningful when ``available`` is False."""
        return "Sandbox is unavailable."


class DisabledSandboxRunner(SandboxRunner):
    """No-op runner used when dynamic analysis is not enabled."""

    available = False

    def unavailable_reason(self) -> str:
        return _DISABLED_MESSAGE

    async def run(self, apk_path: Path, output_dir: Path, *, job_id: str) -> Path:
        raise SandboxDisabledError(_DISABLED_MESSAGE)


class SubprocessSandboxRunner(SandboxRunner):
    """Runs the sandbox as a child process (``compose`` or ``script`` mode)."""

    def __init__(
        self,
        *,
        mode: str,
        sandbox_dir: Path,
        compose_file: Path,
        timeout_secs: int,
        api_level: int,
    ) -> None:
        self.mode = mode
        self.sandbox_dir = sandbox_dir
        self.compose_file = compose_file
        self.timeout_secs = timeout_secs
        self.api_level = api_level

    def build_argv(self, apk_path: Path, output_dir: Path) -> list[str]:
        """Build the sandbox command. Split out from ``run`` so it is testable."""
        if self.mode == "compose":
            # The compose file bind-mounts the APK's directory at /samples (ro)
            # and the artifacts directory at /output, so container-side paths are
            # fixed regardless of where the host files live.
            return [
                "docker",
                "compose",
                "-f",
                str(self.compose_file),
                "run",
                "--rm",
                "sandbox",
                "/opt/sephela/run_analysis.sh",
                f"/samples/{apk_path.name}",
                "/output",
                "--timeout",
                str(self.timeout_secs),
                "--api-level",
                str(self.api_level),
            ]
        if self.mode == "script":
            return [
                str(self.sandbox_dir / "run_analysis.sh"),
                str(apk_path),
                str(output_dir),
                "--timeout",
                str(self.timeout_secs),
                "--api-level",
                str(self.api_level),
            ]
        raise SandboxError(f"Unknown sandbox runner mode: {self.mode!r}")

    def build_env(self, apk_path: Path, output_dir: Path) -> dict[str, str]:
        """Bind-mount sources consumed by docker-compose.sandbox.yml."""
        return {
            "SEPHELA_SAMPLES_DIR": str(apk_path.parent.resolve()),
            "SEPHELA_OUTPUT_DIR": str(output_dir.resolve()),
        }

    async def run(self, apk_path: Path, output_dir: Path, *, job_id: str) -> Path:
        import os

        output_dir.mkdir(parents=True, exist_ok=True)
        argv = self.build_argv(apk_path, output_dir)
        env = {**os.environ, **self.build_env(apk_path, output_dir)}

        if shutil.which(argv[0]) is None and not Path(argv[0]).exists():
            raise SandboxError(f"Sandbox executable not found: {argv[0]}")

        logger.info(
            "sandbox_starting", job_id=job_id, mode=self.mode, timeout_secs=self.timeout_secs
        )
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
            cwd=str(self.sandbox_dir),
        )

        # Grace beyond the in-script timeout so run_analysis.sh gets a chance to
        # clean up its own emulator before we kill it outright.
        budget = self.timeout_secs + settings.sandbox_timeout_grace_secs
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=budget)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise SandboxTimeoutError(
                f"Sandbox exceeded {budget}s wall-clock budget for job {job_id}."
            ) from None

        tail = (stdout or b"").decode("utf-8", errors="replace")[-2000:]
        if proc.returncode != 0:
            raise SandboxError(
                f"Sandbox exited {proc.returncode}. Output tail:\n{tail}"
            )

        produced = [name for name in ARTIFACT_FILES if (output_dir / name).is_file()]
        if not produced:
            raise SandboxError(
                f"Sandbox exited 0 but produced no artifacts in {output_dir}. Output tail:\n{tail}"
            )

        logger.info("sandbox_finished", job_id=job_id, artifacts=produced)
        return output_dir


def get_sandbox_runner() -> SandboxRunner:
    """Build the runner selected by configuration."""
    if not settings.dynamic_enabled or settings.sandbox_runner == "disabled":
        return DisabledSandboxRunner()
    sandbox_dir = Path(settings.sandbox_dir).resolve()
    return SubprocessSandboxRunner(
        mode=settings.sandbox_runner,
        sandbox_dir=sandbox_dir,
        compose_file=sandbox_dir / "docker-compose.sandbox.yml",
        timeout_secs=settings.sandbox_timeout_secs,
        api_level=settings.sandbox_api_level,
    )


def job_artifacts_dir(job_id: uuid.UUID | str) -> Path:
    """Per-job artifacts directory under the configured workspace root."""
    return Path(settings.dynamic_artifacts_root).resolve() / str(job_id)
