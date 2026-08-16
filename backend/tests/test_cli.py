"""Tests for the provisioning CLI's argument handling and password sourcing.

The DB work is exercised by the repository tests; what is worth pinning here is that
a password never has to be typed as an argument, and that a non-interactive run fails
loudly instead of silently provisioning an account with a weak or empty secret.
"""

from __future__ import annotations

import uuid

import pytest

from app.cli import _PASSWORD_ENV, _resolve_password, build_parser
from app.db.models.identity import Role


class TestParser:
    def test_create_user_requires_an_org(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(["create-user", "a@b.c"])

    def test_create_user_defaults_to_the_least_privileged_useful_role(self) -> None:
        # Defaulting to admin would make the safe path the one you have to remember.
        args = build_parser().parse_args(["create-user", "a@b.c", "--org-id", str(uuid.uuid4())])

        assert args.role == Role.analyst.value

    def test_bootstrap_defaults_to_admin(self) -> None:
        # The first user must be able to administer the tenant they just created.
        args = build_parser().parse_args(["bootstrap", "Bank", "a@b.c"])

        assert args.role == Role.admin.value

    def test_an_unknown_role_is_rejected(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(
                ["create-user", "a@b.c", "--org-id", str(uuid.uuid4()), "--role", "root"]
            )

    def test_a_malformed_org_id_is_rejected(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args(["create-user", "a@b.c", "--org-id", "not-a-uuid"])

    def test_there_is_no_password_argument(self) -> None:
        # A password in argv is visible in shell history and in `ps` to every user
        # on the host. Its absence is the control, so assert it stays absent.
        for command in (
            ["create-user", "a@b.c", "--org-id", str(uuid.uuid4())],
            ["bootstrap", "Bank", "a@b.c"],
        ):
            args = build_parser().parse_args(command)
            assert not hasattr(args, "password")


class TestPasswordSourcing:
    def test_generation_produces_a_long_random_secret(self) -> None:
        password, generated = _resolve_password(generate=True)

        assert generated
        assert len(password) >= 24

    def test_generated_secrets_differ_between_runs(self) -> None:
        first, _ = _resolve_password(generate=True)
        second, _ = _resolve_password(generate=True)

        assert first != second

    def test_the_environment_is_used_when_present(self, monkeypatch) -> None:
        monkeypatch.setenv(_PASSWORD_ENV, "from-the-environment")

        password, generated = _resolve_password(generate=False)

        assert password == "from-the-environment"
        assert not generated

    def test_generation_takes_precedence_over_the_environment(self, monkeypatch) -> None:
        monkeypatch.setenv(_PASSWORD_ENV, "from-the-environment")

        password, generated = _resolve_password(generate=True)

        assert generated
        assert password != "from-the-environment"

    def test_a_non_interactive_run_without_a_password_refuses(self, monkeypatch) -> None:
        # Better to fail the deploy step than to create an account whose password
        # is the empty string.
        monkeypatch.delenv(_PASSWORD_ENV, raising=False)
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)

        with pytest.raises(SystemExit, match=_PASSWORD_ENV):
            _resolve_password(generate=False)

    def test_mismatched_prompts_are_rejected(self, monkeypatch) -> None:
        monkeypatch.delenv(_PASSWORD_ENV, raising=False)
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        answers = iter(["first-password", "second-password"])
        monkeypatch.setattr("getpass.getpass", lambda _prompt: next(answers))

        with pytest.raises(SystemExit, match="do not match"):
            _resolve_password(generate=False)

    def test_a_short_password_is_rejected(self, monkeypatch) -> None:
        monkeypatch.delenv(_PASSWORD_ENV, raising=False)
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("getpass.getpass", lambda _prompt: "short")

        with pytest.raises(SystemExit, match="at least"):
            _resolve_password(generate=False)
