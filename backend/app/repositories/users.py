"""Identity persistence — the only place that reads the ``users`` table.

Authentication reads a user row on every request, so these lookups sit on the hot
path for the whole API. Both are indexed single-row fetches by design (``email`` is
unique, ``id`` is the primary key); anything that needs to scan users belongs in an
admin-facing repository, not here.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.identity import Organization, User


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        result = await self.session.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        """Look a user up by email, case-insensitively.

        Addresses are compared lowercased because the local part's case-sensitivity
        is theoretical while "Alice@bank.com fails to log in" is not.
        """
        result = await self.session.execute(select(User).where(User.email == email.strip().lower()))
        return result.scalar_one_or_none()

    async def create(
        self,
        *,
        email: str,
        hashed_password: str | None,
        org_id: uuid.UUID,
        role: str,
        is_active: bool = True,
    ) -> User:
        user = User(
            email=email.strip().lower(),
            hashed_password=hashed_password,
            org_id=org_id,
            role=role,
            is_active=is_active,
        )
        self.session.add(user)
        await self.session.flush()
        return user


class OrganizationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_id(self, org_id: uuid.UUID) -> Organization | None:
        result = await self.session.execute(select(Organization).where(Organization.id == org_id))
        return result.scalar_one_or_none()

    async def create(self, name: str) -> Organization:
        org = Organization(name=name)
        self.session.add(org)
        await self.session.flush()
        return org
