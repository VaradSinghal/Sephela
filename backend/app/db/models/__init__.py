"""Model registry — import all models here so Alembic autogenerate sees them."""

from app.db.models.identity import Organization, Role, User

__all__ = ["Organization", "Role", "User"]
