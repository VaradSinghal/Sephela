"""Administrative CLI — organisation and user provisioning.

Real credential verification creates a bootstrap problem: there is no way to log in
until a user exists, and no authenticated endpoint to create the first one through.
Self-service registration would be the wrong answer for a platform whose tenants are
banks, so provisioning is an operator action performed out-of-band:

    python -m app.cli create-org "Example Bank"
    python -m app.cli create-user admin@bank.example --org-id <uuid> --role admin
    python -m app.cli bootstrap "Example Bank" admin@bank.example   # both at once

Passwords are never accepted as an argument. A password on the command line lands in
the shell history, in ``ps`` output for every user on the box, and in any process
audit — so it is read from ``SEPHELA_INITIAL_PASSWORD`` or prompted for, and a
generated one is printed once for the operator to store.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import secrets
import sys
import uuid

from app.core.security import hash_password
from app.db.models.identity import Role
from app.db.session import AsyncSessionLocal
from app.repositories.users import OrganizationRepository, UserRepository

_PASSWORD_ENV = "SEPHELA_INITIAL_PASSWORD"
_MIN_PASSWORD_LEN = 12


def _resolve_password(*, generate: bool) -> tuple[str, bool]:
    """Return ``(password, was_generated)`` from env, prompt, or generation."""
    if generate:
        return secrets.token_urlsafe(24), True

    from_env = os.getenv(_PASSWORD_ENV)
    if from_env:
        return from_env, False

    if not sys.stdin.isatty():
        raise SystemExit(
            f"No password available: set {_PASSWORD_ENV}, pass --generate-password, "
            "or run interactively."
        )

    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Confirm password: "):
        raise SystemExit("Passwords do not match.")
    if len(first) < _MIN_PASSWORD_LEN:
        raise SystemExit(f"Password must be at least {_MIN_PASSWORD_LEN} characters.")
    return first, False


async def _create_org(name: str) -> None:
    async with AsyncSessionLocal() as session:
        org = await OrganizationRepository(session).create(name)
        await session.commit()
        print(f"organization created\n  id:   {org.id}\n  name: {org.name}")


async def _create_user(email: str, org_id: uuid.UUID, role: str, *, generate: bool) -> None:
    password, generated = _resolve_password(generate=generate)

    async with AsyncSessionLocal() as session:
        users = UserRepository(session)
        if await users.get_by_email(email):
            raise SystemExit(f"A user with email {email!r} already exists.")
        if await OrganizationRepository(session).get_by_id(org_id) is None:
            # Checked explicitly: the FK violation would otherwise surface as an
            # opaque IntegrityError after the password prompt.
            raise SystemExit(f"No organization with id {org_id}.")

        user = await users.create(
            email=email,
            hashed_password=hash_password(password),
            org_id=org_id,
            role=role,
        )
        await session.commit()

    print(f"user created\n  id:    {user.id}\n  email: {user.email}\n  role:  {role}")
    if generated:
        print(f"  password (shown once): {password}")


async def _bootstrap(org_name: str, email: str, role: str, *, generate: bool) -> None:
    password, generated = _resolve_password(generate=generate)

    async with AsyncSessionLocal() as session:
        users = UserRepository(session)
        if await users.get_by_email(email):
            raise SystemExit(f"A user with email {email!r} already exists.")

        org = await OrganizationRepository(session).create(org_name)
        user = await users.create(
            email=email,
            hashed_password=hash_password(password),
            org_id=org.id,
            role=role,
        )
        await session.commit()

    print(
        f"bootstrapped\n  org:   {org.id} ({org.name})\n"
        f"  user:  {user.id} ({user.email})\n  role:  {role}"
    )
    if generated:
        print(f"  password (shown once): {password}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    org = sub.add_parser("create-org", help="Create an organisation (tenant).")
    org.add_argument("name")

    user = sub.add_parser("create-user", help="Create a user in an organisation.")
    user.add_argument("email")
    user.add_argument("--org-id", required=True, type=uuid.UUID)
    user.add_argument("--role", default=Role.analyst.value, choices=[r.value for r in Role])
    user.add_argument(
        "--generate-password",
        action="store_true",
        help="Generate a strong password and print it once.",
    )

    boot = sub.add_parser("bootstrap", help="Create an organisation and its first user together.")
    boot.add_argument("org_name")
    boot.add_argument("email")
    boot.add_argument("--role", default=Role.admin.value, choices=[r.value for r in Role])
    boot.add_argument("--generate-password", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    if args.command == "create-org":
        asyncio.run(_create_org(args.name))
    elif args.command == "create-user":
        asyncio.run(
            _create_user(args.email, args.org_id, args.role, generate=args.generate_password)
        )
    elif args.command == "bootstrap":
        asyncio.run(
            _bootstrap(args.org_name, args.email, args.role, generate=args.generate_password)
        )


if __name__ == "__main__":
    main()
