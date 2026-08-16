"""Tests for the boot-time refusal to run on placeholder secrets.

A default signing key is the kind of misconfiguration that never announces itself:
tokens still sign, requests still succeed, and nothing breaks until someone forges a
token with the well-known key. The only reliable moment to catch it is startup.
"""

from __future__ import annotations

import pytest

from app.core.config import Settings, assert_production_ready
from app.core.exceptions import ConfigurationError


def _settings(**overrides) -> Settings:
    base = {
        "env": "prod",
        "secret_key": "a-real-secret",
        "postgres_password": "a-real-password",
    }
    return Settings(**{**base, **overrides})


class TestLocal:
    def test_placeholder_secrets_are_tolerated_locally(self) -> None:
        # Requiring real secrets to run the test suite or a laptop stack would get
        # the check disabled rather than satisfied.
        assert_production_ready(_settings(env="local", secret_key="change-me"))

    def test_dev_is_not_exempt(self) -> None:
        # `dev` is a deployed K8s namespace (doc 08), not a developer laptop — the
        # name invites the opposite assumption, so pin it.
        with pytest.raises(ConfigurationError):
            assert_production_ready(_settings(env="dev", secret_key="change-me"))


class TestDeployedEnvironments:
    @pytest.mark.parametrize("env", ["dev", "staging", "prod"])
    def test_a_default_signing_key_refuses_to_boot(self, env: str) -> None:
        with pytest.raises(ConfigurationError, match="secret_key"):
            assert_production_ready(_settings(env=env, secret_key="change-me"))

    def test_a_default_database_password_refuses_to_boot(self) -> None:
        with pytest.raises(ConfigurationError, match="postgres_password"):
            assert_production_ready(_settings(postgres_password="sephela"))

    def test_every_offender_is_named_at_once(self) -> None:
        # One restart per secret is a bad way to learn the list.
        with pytest.raises(ConfigurationError) as exc:
            assert_production_ready(_settings(secret_key="change-me", postgres_password="sephela"))

        assert "secret_key" in str(exc.value)
        assert "postgres_password" in str(exc.value)

    def test_real_secrets_boot_cleanly(self) -> None:
        assert_production_ready(_settings())

    def test_the_error_names_the_environment(self) -> None:
        with pytest.raises(ConfigurationError, match="staging"):
            assert_production_ready(_settings(env="staging", secret_key="change-me"))
