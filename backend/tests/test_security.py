"""Tests for password hashing, tokens, principal resolution, and the role ladder.

The properties pinned here are the ones whose absence is invisible in normal use: a
token whose claims are trusted still authenticates the right person most of the
time, and a truncating password hash still logs the right user in. Each test below
corresponds to a way the Phase-2 placeholder was wrong.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.core.exceptions import ForbiddenError, UnauthorizedError
from app.core.security import (
    ACCESS,
    REFRESH,
    CurrentUser,
    _encode,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    resolve_principal,
    verify_password,
)
from app.db.models.identity import Role, User


def _user(
    *,
    role: Role = Role.analyst,
    is_active: bool = True,
    org_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
) -> User:
    return User(
        id=user_id or uuid.uuid4(),
        email="analyst@bank.example",
        hashed_password=hash_password("pw"),
        org_id=org_id or uuid.uuid4(),
        role=role,
        is_active=is_active,
    )


class FakeUserRepo:
    """Stands in for UserRepository; records what was asked for."""

    def __init__(self, user: User | None = None) -> None:
        self.user = user
        self.requested_id: uuid.UUID | None = None

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        self.requested_id = user_id
        return self.user

    async def get_by_email(self, email: str) -> User | None:
        return self.user


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------


class TestPasswordHashing:
    def test_a_password_verifies_against_its_own_hash(self) -> None:
        assert verify_password("s3cret", hash_password("s3cret"))

    def test_a_wrong_password_does_not_verify(self) -> None:
        assert not verify_password("wrong", hash_password("s3cret"))

    def test_the_same_password_hashes_differently_each_time(self) -> None:
        # Per-hash salt: identical stored hashes would reveal that two users share
        # a password.
        assert hash_password("same") != hash_password("same")

    def test_passwords_differing_past_72_bytes_are_distinguished(self) -> None:
        # Raw bcrypt ignores everything after byte 72, so these two would validate
        # against each other's hash. The SHA-256 pre-hash is what prevents that.
        base = "x" * 80
        stored = hash_password(base + "TAIL-A")

        assert verify_password(base + "TAIL-A", stored)
        assert not verify_password(base + "TAIL-B", stored)

    def test_a_long_passphrase_is_usable_at_all(self) -> None:
        # Plain bcrypt raises above 72 bytes; a login must not 500 because the user
        # chose a sentence.
        long_phrase = "correct horse battery staple " * 10
        assert verify_password(long_phrase, hash_password(long_phrase))

    @pytest.mark.parametrize("stored", ["", "not-a-hash", "$2b$12$too-short"])
    def test_a_corrupt_stored_hash_fails_closed(self, stored: str) -> None:
        # It must reject rather than raise: a 500 here both breaks the login and
        # distinguishes this row from a nonexistent one.
        assert verify_password("anything", stored) is False


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


class TestTokens:
    def test_an_access_token_round_trips(self) -> None:
        token = create_access_token("user-1", claims={"email": "a@b.c"})
        claims = decode_token(token, expect=ACCESS)

        assert claims["sub"] == "user-1"
        assert claims["typ"] == ACCESS

    def test_a_refresh_token_is_rejected_where_an_access_token_is_required(self) -> None:
        # Otherwise the long-lived refresh token doubles as an access token and the
        # short access TTL buys nothing.
        refresh = create_refresh_token("user-1")

        with pytest.raises(UnauthorizedError):
            decode_token(refresh, expect=ACCESS)

    def test_an_access_token_is_rejected_where_a_refresh_token_is_required(self) -> None:
        access = create_access_token("user-1")

        with pytest.raises(UnauthorizedError):
            decode_token(access, expect=REFRESH)

    def test_each_token_carries_a_distinct_id(self) -> None:
        # jti gives a future revocation list something to key on per token.
        first = decode_token(create_access_token("user-1"))
        second = decode_token(create_access_token("user-1"))

        assert first["jti"] != second["jti"]

    def test_an_expired_token_is_rejected(self) -> None:
        expired = _encode("user-1", ACCESS, timedelta(seconds=-30), None)

        with pytest.raises(UnauthorizedError):
            decode_token(expired)

    def test_a_tampered_token_is_rejected(self) -> None:
        token = create_access_token("user-1")
        header, payload, signature = token.split(".")
        forged = f"{header}.{payload}.{signature[:-4]}AAAA"

        with pytest.raises(UnauthorizedError):
            decode_token(forged)

    def test_a_token_signed_with_another_key_is_rejected(self) -> None:
        from jose import jwt

        alien = jwt.encode({"sub": "user-1", "typ": ACCESS}, "not-our-key", algorithm="HS256")

        with pytest.raises(UnauthorizedError):
            decode_token(alien)


# ---------------------------------------------------------------------------
# Principal resolution
# ---------------------------------------------------------------------------


class TestPrincipalResolution:
    async def test_the_principal_is_built_from_the_database_row(self) -> None:
        user = _user(role=Role.viewer)
        repo = FakeUserRepo(user)

        principal = await resolve_principal(create_access_token(str(user.id)), repo)

        assert principal.id == str(user.id)
        assert principal.role == Role.viewer.value
        assert principal.org_id == str(user.org_id)

    async def test_role_and_org_claims_in_the_token_are_ignored(self) -> None:
        # The core Phase-2 hole: a signed token asserting admin on another tenant.
        # Authorization must come from the row, so these claims are inert.
        user = _user(role=Role.viewer)
        repo = FakeUserRepo(user)
        forged = create_access_token(
            str(user.id), claims={"role": "admin", "org_id": str(uuid.uuid4())}
        )

        principal = await resolve_principal(forged, repo)

        assert principal.role == Role.viewer.value
        assert principal.org_id == str(user.org_id)

    async def test_a_deactivated_user_is_rejected_before_their_token_expires(self) -> None:
        user = _user(is_active=False)
        repo = FakeUserRepo(user)

        with pytest.raises(UnauthorizedError, match="disabled"):
            await resolve_principal(create_access_token(str(user.id)), repo)

    async def test_a_token_for_a_deleted_user_is_rejected(self) -> None:
        repo = FakeUserRepo(None)

        with pytest.raises(UnauthorizedError, match="known user"):
            await resolve_principal(create_access_token(str(uuid.uuid4())), repo)

    async def test_a_legacy_token_with_an_email_subject_is_rejected(self) -> None:
        # The placeholder minted tokens whose `sub` was an email. Those must stop
        # working rather than being interpreted as some user.
        repo = FakeUserRepo(_user())

        with pytest.raises(UnauthorizedError, match="not a user id"):
            await resolve_principal(create_access_token("analyst@bank.example"), repo)

    async def test_the_user_is_looked_up_by_the_token_subject(self) -> None:
        user = _user()
        repo = FakeUserRepo(user)

        await resolve_principal(create_access_token(str(user.id)), repo)

        assert repo.requested_id == user.id


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


class TestRoleLadder:
    @pytest.mark.parametrize(
        ("role", "minimum", "allowed"),
        [
            (Role.admin, Role.viewer, True),
            (Role.admin, Role.analyst, True),
            (Role.admin, Role.admin, True),
            (Role.analyst, Role.viewer, True),
            (Role.analyst, Role.analyst, True),
            (Role.analyst, Role.admin, False),
            (Role.viewer, Role.viewer, True),
            (Role.viewer, Role.analyst, False),
            (Role.viewer, Role.admin, False),
        ],
    )
    def test_privilege_is_ordered_not_exact(self, role: Role, minimum: Role, allowed: bool) -> None:
        principal = CurrentUser(id="1", email="a@b.c", role=role.value)

        assert principal.has_role(minimum) is allowed

    def test_an_unrecognised_role_is_denied_everything(self) -> None:
        # Fail closed: a role string the ladder does not know must not inherit
        # viewer's permissions by accident.
        principal = CurrentUser(id="1", email="a@b.c", role="superuser")

        assert not principal.has_role(Role.viewer)

    async def test_require_role_admits_a_sufficient_principal(self) -> None:
        from app.core.security import require_role

        guard = require_role(Role.analyst)
        principal = CurrentUser(id="1", email="a@b.c", role=Role.admin.value)

        assert await guard(principal) is principal

    async def test_require_role_rejects_an_insufficient_principal(self) -> None:
        from app.core.security import require_role

        guard = require_role(Role.analyst)
        principal = CurrentUser(id="1", email="a@b.c", role=Role.viewer.value)

        with pytest.raises(ForbiddenError, match="analyst"):
            await guard(principal)


class TestOrgUuid:
    def test_org_uuid_parses_the_string_form(self) -> None:
        org = uuid.uuid4()
        principal = CurrentUser(id="1", email="a@b.c", role="viewer", org_id=str(org))

        assert principal.org_uuid == org

    def test_a_principal_without_an_org_has_no_org_uuid(self) -> None:
        principal = CurrentUser(id="1", email="a@b.c", role="viewer")

        assert principal.org_uuid is None
