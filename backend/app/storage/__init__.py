"""Storage backend factory — selects the backend from settings."""

from __future__ import annotations

from functools import lru_cache

from app.core.config import settings
from app.storage.base import StorageBackend
from app.storage.local import LocalStorage
from app.storage.s3 import S3ConfigurationError, S3Storage


@lru_cache
def get_storage() -> StorageBackend:
    if settings.storage_backend == "local":
        return LocalStorage(settings.storage_local_root)
    if settings.storage_backend == "s3":
        # Credentials may legitimately be absent: on EKS with IRSA, or on EC2 with an
        # instance profile, boto3 resolves them from the environment and passing None
        # is how you ask it to. A missing *bucket* is never legitimate, and
        # S3Storage refuses that at construction.
        return S3Storage(
            bucket=settings.s3_bucket,
            region=settings.s3_region,
            endpoint_url=settings.s3_endpoint_url,
            access_key=settings.s3_access_key,
            secret_key=settings.s3_secret_key,
        )
    raise ValueError(f"Unknown storage backend: {settings.storage_backend}")


__all__ = ["S3ConfigurationError", "S3Storage", "StorageBackend", "get_storage"]
