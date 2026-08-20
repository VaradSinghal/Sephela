"""Fixtures for the static-analysis extractors.

Two kinds of double, matching the two kinds of extractor:

- Tool-free extractors read ``ctx.data`` and ``ctx.zip``, so they get a *real* ZIP
  built in ``tmp_path``. An APK is a ZIP, so this exercises the real archive reading
  rather than a mock of it.
- Androguard-backed extractors read ``ctx.androguard_apk()``, which returns the
  ``_apk_obj`` field if it is already set. So a hand-written stand-in injects cleanly
  and the tests need neither androguard nor a real signed APK.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from sephela_static.base import ExtractionContext


class FakeApk:
    """An androguard ``APK``, as far as the extractors actually use it.

    Written out rather than mocked so that a change to what an extractor reads shows
    up as an ``AttributeError`` here instead of a mock silently answering.
    """

    def __init__(
        self,
        *,
        package: str = "com.example.app",
        version_name: str = "1.0.0",
        version_code: str = "1",
        min_sdk: str = "21",
        target_sdk: str = "33",
        main_activity: str = "com.example.app.MainActivity",
        permissions: list[str] | None = None,
        activities: list[str] | None = None,
        services: list[str] | None = None,
        receivers: list[str] | None = None,
        providers: list[str] | None = None,
        intent_filters: dict[str, Any] | None = None,
        intent_filters_raise: bool = False,
        certificates: list[Any] | None = None,
        certificates_raise: bool = False,
        dexes: list[bytes] | None = None,
    ) -> None:
        self._package = package
        self._version_name = version_name
        self._version_code = version_code
        self._min_sdk = min_sdk
        self._target_sdk = target_sdk
        self._main_activity = main_activity
        self._permissions = permissions or []
        self._activities = activities or []
        self._services = services or []
        self._receivers = receivers or []
        self._providers = providers or []
        self._intent_filters = intent_filters or {}
        self._intent_filters_raise = intent_filters_raise
        self._certificates = certificates or []
        self._certificates_raise = certificates_raise
        self._dexes = dexes or []

    def get_package(self) -> str:
        return self._package

    def get_androidversion_name(self) -> str:
        return self._version_name

    def get_androidversion_code(self) -> str:
        return self._version_code

    def get_min_sdk_version(self) -> str:
        return self._min_sdk

    def get_target_sdk_version(self) -> str:
        return self._target_sdk

    def get_main_activity(self) -> str:
        return self._main_activity

    def get_permissions(self) -> list[str]:
        return list(self._permissions)

    def get_activities(self) -> list[str]:
        return list(self._activities)

    def get_services(self) -> list[str]:
        return list(self._services)

    def get_receivers(self) -> list[str]:
        return list(self._receivers)

    def get_providers(self) -> list[str]:
        return list(self._providers)

    def get_intent_filters(self, kind: str, component: str) -> Any:
        if self._intent_filters_raise:
            raise RuntimeError("androguard intent-filter API changed")
        return self._intent_filters.get(component)

    def get_certificates(self) -> list[Any]:
        if self._certificates_raise:
            raise RuntimeError("unsupported signature scheme")
        return list(self._certificates)

    def get_all_dex(self):
        yield from self._dexes


class FakeName:
    """An ``asn1crypto`` name, which exposes ``human_friendly``."""

    def __init__(self, value: str) -> None:
        self.human_friendly = value


class FakeCertificate:
    """An androguard certificate, as far as ``CertificateExtractor`` reads it."""

    def __init__(
        self,
        *,
        subject: str = "CN=Example, O=Example Ltd",
        issuer: str = "CN=Real CA, O=CA Ltd",
        serial_number: int = 1234567890,
        sha256: bytes | None = b"\xab" * 32,
        not_valid_before: str = "2026-01-01 00:00:00",
        not_valid_after: str = "2027-01-01 00:00:00",
    ) -> None:
        self.subject = FakeName(subject)
        self.issuer = FakeName(issuer)
        self.serial_number = serial_number
        self.not_valid_before = not_valid_before
        self.not_valid_after = not_valid_after
        if sha256 is not None:
            self.sha256 = sha256


@pytest.fixture
def make_apk_zip(tmp_path: Path):
    """Build a real ZIP with the entries given, and return its path.

    An APK is a ZIP, so the tool-free extractors run against the real thing.
    """

    def _build(entries: dict[str, bytes] | None = None, name: str = "sample.apk") -> Path:
        path = tmp_path / name
        with zipfile.ZipFile(path, "w") as archive:
            for entry_name, blob in (entries or {}).items():
                archive.writestr(entry_name, blob)
        return path

    return _build


@pytest.fixture
def make_context(make_apk_zip):
    """An ``ExtractionContext`` over a real ZIP, optionally with a fake APK object."""

    def _build(
        entries: dict[str, bytes] | None = None,
        *,
        apk: Any = None,
        shared: dict[str, Any] | None = None,
    ) -> ExtractionContext:
        return ExtractionContext(
            apk_path=make_apk_zip(entries),
            shared=shared or {},
            _apk_obj=apk,
        )

    return _build
