"""APK validation + hashing (Phase 4).

Lightweight, dependency-free structural validation — enough to reject
non-APKs early and compute content hashes. Deep parsing (manifest, package
name, certs) belongs to the Static Analysis Engine (Phase 5), NOT here.
"""

from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass
from io import BytesIO

from app.core.exceptions import ValidationAppError

# APK = ZIP; a valid one must contain the Android manifest entry.
ANDROID_MANIFEST = "AndroidManifest.xml"
ZIP_MAGIC = b"PK\x03\x04"


@dataclass(frozen=True)
class ApkHashes:
    sha256: str
    sha1: str
    md5: str
    size: int


def compute_hashes(data: bytes) -> ApkHashes:
    # sha1/md5 are sample *identifiers*, not integrity checks: AV vendors and
    # threat-intel feeds (URLhaus, MalwareBazaar) key on them, so we must emit
    # them to correlate. sha256 is the one used as the content-addressed key.
    # Hence usedforsecurity=False — it is the accurate declaration, not a waiver.
    return ApkHashes(
        sha256=hashlib.sha256(data).hexdigest(),
        sha1=hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        size=len(data),
    )


def validate_apk(data: bytes, *, filename: str | None = None) -> None:
    """Reject anything that isn't a structurally-valid APK.

    Raises ``ValidationAppError`` with a clear reason. Does not open/parse the
    manifest contents — only confirms the ZIP structure and required entry.
    """
    if not data:
        raise ValidationAppError("Uploaded file is empty.")
    if not data.startswith(ZIP_MAGIC):
        raise ValidationAppError("File is not a valid APK (missing ZIP signature).")

    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            if zf.testzip() is not None:
                raise ValidationAppError("APK archive is corrupt.")
            names = set(zf.namelist())
    except zipfile.BadZipFile as exc:
        raise ValidationAppError("File is not a valid ZIP/APK archive.") from exc

    if ANDROID_MANIFEST not in names:
        raise ValidationAppError("Archive is missing AndroidManifest.xml — not an APK.")
