"""S3-compatible storage backend (AWS S3 / MinIO).

The backend the platform needs to run on more than one worker. ``LocalStorage`` puts
bytes on the worker's own disk, so with two workers the stage that uploads a sample
and the stage that reads it are only sometimes the same machine.

Synchronous ``boto3`` wrapped in ``asyncio.to_thread``, not ``aioboto3``: it is the
pattern ``LocalStorage`` already uses, and boto3 is the client whose retry, signing,
and endpoint handling is worth inheriting rather than reimplementing over a second
async HTTP stack.
"""

from __future__ import annotations

import asyncio
from typing import Any, cast

from botocore.config import Config
from botocore.exceptions import ClientError

from app.storage.base import StorageBackend

#: Status codes and error codes that mean "the object is not there", as opposed to
#: "the request failed". They have to be mapped to ``FileNotFoundError`` because that
#: is the contract callers were written against: ``materialize_apk`` documents it and
#: ``app.tasks.static`` catches it to fail one stage cleanly instead of the job.
_MISSING_ERROR_CODES = frozenset({"404", "NoSuchKey", "NotFound"})


class S3ConfigurationError(RuntimeError):
    """The S3 backend was selected without the settings it needs."""


class S3Storage(StorageBackend):
    """Content-addressed blob storage on an S3-compatible endpoint."""

    def __init__(
        self,
        bucket: str,
        *,
        region: str = "us-east-1",
        endpoint_url: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
    ) -> None:
        if not bucket:
            raise S3ConfigurationError("S3 storage requires SEPHELA_S3_BUCKET.")

        self.bucket = bucket
        self.endpoint_url = endpoint_url

        import boto3

        self._client: Any = boto3.client(
            "s3",
            region_name=region,
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(
                # MinIO serves buckets as a path, not a subdomain, and a
                # virtual-host-style request against it 404s on every key.
                s3={"addressing_style": "path" if endpoint_url else "auto"},
                # Samples are up to 300 MiB, so a transfer is not a short request.
                retries={"max_attempts": 3, "mode": "standard"},
                connect_timeout=10,
                read_timeout=120,
            ),
        )

    # ------------------------------------------------------------------
    # StorageBackend
    # ------------------------------------------------------------------

    async def save(self, key: str, data: bytes) -> str:
        def _put() -> None:
            self._client.put_object(Bucket=self.bucket, Key=key, Body=data)

        await asyncio.to_thread(_put)
        return self.uri_for(key)

    async def load(self, key: str) -> bytes:
        def _get() -> bytes:
            try:
                response = self._client.get_object(Bucket=self.bucket, Key=key)
            except ClientError as exc:
                raise self._translate(exc, key) from exc
            body: bytes = response["Body"].read()
            return body

        return await asyncio.to_thread(_get)

    async def exists(self, key: str) -> bool:
        def _head() -> bool:
            try:
                self._client.head_object(Bucket=self.bucket, Key=key)
            except ClientError as exc:
                if _is_missing(exc):
                    return False
                raise
            return True

        return await asyncio.to_thread(_head)

    async def delete(self, key: str) -> None:
        def _delete() -> None:
            # S3 DELETE is already idempotent — a missing key is a 204 — so this
            # matches LocalStorage's missing_ok=True without a pre-flight HEAD.
            self._client.delete_object(Bucket=self.bucket, Key=key)

        await asyncio.to_thread(_delete)

    def uri_for(self, key: str) -> str:
        """An ``s3://`` URI, or an endpoint-qualified one for a non-AWS endpoint.

        A bare ``s3://bucket/key`` is ambiguous once MinIO is in play: the same
        bucket and key name exist on a different server. The stored URI is what an
        operator reads when reconciling a sample against its bytes, so it names the
        endpoint when there is one.
        """
        if self.endpoint_url:
            return f"{self.endpoint_url.rstrip('/')}/{self.bucket}/{key}"
        return f"s3://{self.bucket}/{key}"

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _translate(self, exc: ClientError, key: str) -> Exception:
        """Map a missing object to ``FileNotFoundError``, leaving real errors alone.

        Collapsing every ``ClientError`` would be worse than not translating at all:
        an expired credential or a denied bucket policy would then read as "the
        sample was never uploaded", and the stage would report a clean, wrong reason.
        """
        if _is_missing(exc):
            return FileNotFoundError(f"s3://{self.bucket}/{key}")
        return cast("Exception", exc)


def _is_missing(exc: ClientError) -> bool:
    error: Any = exc.response.get("Error", {})
    if str(error.get("Code")) in _MISSING_ERROR_CODES:
        return True
    metadata: Any = exc.response.get("ResponseMetadata", {})
    return bool(metadata.get("HTTPStatusCode") == 404)
