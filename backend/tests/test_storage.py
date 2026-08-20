"""Tests for the local storage backend + content-addressed keys."""

from __future__ import annotations

import pytest

from app.storage.base import StorageBackend
from app.storage.local import LocalStorage


def test_sample_key_is_sharded() -> None:
    sha = "ab" + "c" * 62
    key = StorageBackend.sample_key(sha)
    assert key == f"samples/ab/cc/{sha}.apk"


@pytest.mark.asyncio
async def test_local_roundtrip(tmp_path) -> None:
    store = LocalStorage(tmp_path)
    key = "samples/aa/bb/deadbeef.apk"
    assert not await store.exists(key)

    uri = await store.save(key, b"hello-apk")
    assert uri.startswith("file://")
    assert await store.exists(key)
    assert await store.load(key) == b"hello-apk"

    await store.delete(key)
    assert not await store.exists(key)
    await store.delete(key)  # idempotent


# ---------------------------------------------------------------------------
# Key layout
# ---------------------------------------------------------------------------


def test_report_key_is_keyed_by_job_not_content() -> None:
    # Two runs of the same sample are different jobs and must keep their own reports,
    # because the analysis — and therefore the score — can legitimately differ.
    job = "12345678-1234-5678-1234-567812345678"
    assert StorageBackend.report_key(job, "report.pdf") == f"reports/12/{job}/report.pdf"


def test_artifact_key_is_keyed_by_job() -> None:
    job = "abcdef12-1234-5678-1234-567812345678"
    assert StorageBackend.artifact_key(job, "jadx.tar.gz") == f"artifacts/ab/{job}/jadx.tar.gz"


def test_samples_reports_and_artifacts_never_collide() -> None:
    # They have different retention rules — samples are kept, artifacts are deleted by
    # the last stage that reads them — so sharing a prefix would make a lifecycle rule
    # on one silently apply to another.
    sha = "a" * 64
    job = "b" * 8 + "-1234-5678-1234-567812345678"
    prefixes = {
        StorageBackend.sample_key(sha).split("/")[0],
        StorageBackend.report_key(job, "r.json").split("/")[0],
        StorageBackend.artifact_key(job, "a.tar.gz").split("/")[0],
    }
    assert len(prefixes) == 3


@pytest.mark.asyncio
async def test_local_uri_for_matches_what_save_returns(tmp_path) -> None:
    # The upload service records uri_for(key) when the bytes are already stored, so a
    # divergence here would make two rows for the same sample disagree about location.
    store = LocalStorage(tmp_path)
    key = "samples/aa/bb/deadbeef.apk"

    saved = await store.save(key, b"x")

    assert store.uri_for(key) == saved


# ---------------------------------------------------------------------------
# S3 / MinIO
# ---------------------------------------------------------------------------

moto = pytest.importorskip("moto")
BUCKET = "sephela-test"


@pytest.fixture
def s3_store(monkeypatch):
    """An S3Storage against moto's in-process S3. No network, no credentials."""
    from moto import mock_aws

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    with mock_aws():
        import boto3

        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=BUCKET)

        from app.storage.s3 import S3Storage

        yield S3Storage(bucket=BUCKET, region="us-east-1")


class TestS3Roundtrip:
    @pytest.mark.asyncio
    async def test_save_load_exists_delete(self, s3_store) -> None:
        key = StorageBackend.sample_key("c" * 64)
        assert not await s3_store.exists(key)

        uri = await s3_store.save(key, b"hello-apk")

        assert uri == f"s3://{BUCKET}/{key}"
        assert await s3_store.exists(key)
        assert await s3_store.load(key) == b"hello-apk"

        await s3_store.delete(key)
        assert not await s3_store.exists(key)

    @pytest.mark.asyncio
    async def test_delete_is_idempotent(self, s3_store) -> None:
        # LocalStorage uses missing_ok=True; the two backends must agree, because
        # cleanup paths call delete without checking first.
        await s3_store.delete("artifacts/no/such/key")

    @pytest.mark.asyncio
    async def test_a_missing_key_raises_file_not_found(self, s3_store) -> None:
        # The contract materialize_apk documents and app.tasks.static catches to fail
        # one stage cleanly instead of the whole job. A bare ClientError here would
        # escape as an unhandled infrastructure error.
        with pytest.raises(FileNotFoundError):
            await s3_store.load("samples/no/such/key.apk")

    @pytest.mark.asyncio
    async def test_the_not_found_message_names_the_object(self, s3_store) -> None:
        with pytest.raises(FileNotFoundError, match=BUCKET):
            await s3_store.load("samples/no/such/key.apk")

    @pytest.mark.asyncio
    async def test_overwriting_a_key_replaces_the_bytes(self, s3_store) -> None:
        key = StorageBackend.artifact_key("job-1", "a.bin")

        await s3_store.save(key, b"first")
        await s3_store.save(key, b"second")

        assert await s3_store.load(key) == b"second"

    @pytest.mark.asyncio
    async def test_binary_content_survives_unchanged(self, s3_store) -> None:
        # APKs are ZIPs; any text-mode handling anywhere would corrupt them.
        blob = bytes(range(256)) * 40
        key = StorageBackend.sample_key("d" * 64)

        await s3_store.save(key, blob)

        assert await s3_store.load(key) == blob

    @pytest.mark.asyncio
    async def test_uri_for_matches_what_save_returns(self, s3_store) -> None:
        key = StorageBackend.sample_key("e" * 64)

        assert await s3_store.save(key, b"x") == s3_store.uri_for(key)


class TestS3ErrorTranslation:
    """A real failure must not be reported as a missing sample."""

    @pytest.mark.asyncio
    async def test_an_access_denied_is_not_translated_to_not_found(self, s3_store) -> None:
        # Reporting "APK bytes missing from storage" for an expired credential or a
        # denied bucket policy sends an operator looking in exactly the wrong place.
        from botocore.exceptions import ClientError

        denied = ClientError(
            {
                "Error": {"Code": "AccessDenied", "Message": "Access Denied"},
                "ResponseMetadata": {"HTTPStatusCode": 403},
            },
            "GetObject",
        )
        s3_store._client.get_object = lambda **_: (_ for _ in ()).throw(denied)

        with pytest.raises(ClientError):
            await s3_store.load("samples/aa/bb/x.apk")

    @pytest.mark.asyncio
    async def test_exists_propagates_a_real_error_rather_than_answering_false(
        self, s3_store
    ) -> None:
        # `False` here would let the upload service re-upload into a bucket it cannot
        # write to, and the readiness probe would report storage healthy.
        from botocore.exceptions import ClientError

        denied = ClientError(
            {"Error": {"Code": "AccessDenied"}, "ResponseMetadata": {"HTTPStatusCode": 403}},
            "HeadObject",
        )
        s3_store._client.head_object = lambda **_: (_ for _ in ()).throw(denied)

        with pytest.raises(ClientError):
            await s3_store.exists("samples/aa/bb/x.apk")


class TestS3Configuration:
    def test_a_missing_bucket_is_refused_at_construction(self) -> None:
        from app.storage.s3 import S3ConfigurationError, S3Storage

        with pytest.raises(S3ConfigurationError, match="BUCKET"):
            S3Storage(bucket="")

    def test_a_minio_endpoint_is_addressed_path_style(self) -> None:
        # MinIO serves buckets as a path, not a subdomain; virtual-host addressing
        # against it 404s on every key.
        from app.storage.s3 import S3Storage

        store = S3Storage(bucket=BUCKET, endpoint_url="http://minio:9000")

        assert store._client.meta.config.s3["addressing_style"] == "path"

    def test_aws_uses_the_default_addressing_style(self) -> None:
        from app.storage.s3 import S3Storage

        store = S3Storage(bucket=BUCKET)

        assert store._client.meta.config.s3["addressing_style"] == "auto"

    def test_a_custom_endpoint_is_named_in_the_uri(self) -> None:
        # `s3://bucket/key` is ambiguous once MinIO exists: the same bucket and key
        # name also exist on a different server. The stored URI is what an operator
        # reads when reconciling a sample against its bytes.
        from app.storage.s3 import S3Storage

        store = S3Storage(bucket=BUCKET, endpoint_url="http://minio:9000/")

        assert store.uri_for("samples/a/b/c.apk") == f"http://minio:9000/{BUCKET}/samples/a/b/c.apk"


class TestStorageFactory:
    def test_s3_is_selected_and_no_longer_raises(self, monkeypatch) -> None:
        # It used to raise NotImplementedError, which made every non-local deployment
        # impossible.
        from app.storage import get_storage
        from app.storage.s3 import S3Storage

        get_storage.cache_clear()
        monkeypatch.setattr("app.storage.settings.storage_backend", "s3")
        monkeypatch.setattr("app.storage.settings.s3_bucket", BUCKET)
        try:
            assert isinstance(get_storage(), S3Storage)
        finally:
            get_storage.cache_clear()

    def test_local_is_still_the_default_selection(self, monkeypatch, tmp_path) -> None:
        from app.storage import get_storage

        get_storage.cache_clear()
        monkeypatch.setattr("app.storage.settings.storage_backend", "local")
        monkeypatch.setattr("app.storage.settings.storage_local_root", str(tmp_path))
        try:
            assert isinstance(get_storage(), LocalStorage)
        finally:
            get_storage.cache_clear()

    def test_an_unknown_backend_is_rejected(self, monkeypatch) -> None:
        from app.storage import get_storage

        get_storage.cache_clear()
        monkeypatch.setattr("app.storage.settings.storage_backend", "gcs")
        try:
            with pytest.raises(ValueError, match="gcs"):
                get_storage()
        finally:
            get_storage.cache_clear()
