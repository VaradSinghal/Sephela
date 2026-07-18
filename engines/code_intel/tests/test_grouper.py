"""Tests for the logical grouper analyzer."""

from __future__ import annotations

from sephela_code_intel.analyzers.grouper import GrouperAnalyzer, _classify_to_group
from sephela_code_intel.base import AnalysisContext


def test_classify_networking() -> None:
    assert _classify_to_group("com.app.network.ApiClient", []) == "networking"
    assert _classify_to_group("com.app.http.RequestManager", []) == "networking"


def test_classify_persistence() -> None:
    assert _classify_to_group("com.app.database.UserDao", []) == "persistence"
    assert _classify_to_group("com.app.db.CacheStore", []) == "persistence"


def test_classify_crypto() -> None:
    assert _classify_to_group("com.app.crypto.AesHelper", []) == "crypto"
    assert _classify_to_group("com.app.cipher.Decryptor", []) == "crypto"


def test_classify_ui() -> None:
    assert _classify_to_group("com.app.activity.LoginActivity", []) == "ui"
    assert _classify_to_group("com.app.fragment.HomeFragment", []) == "ui"


def test_classify_receivers() -> None:
    assert _classify_to_group("com.app.receiver.SmsReceiver", []) == "receivers"
    assert _classify_to_group("com.app.broadcast.BootReceiver", []) == "receivers"


def test_classify_services() -> None:
    assert _classify_to_group("com.app.service.SyncService", []) == "services"
    assert _classify_to_group("com.app.background.WorkerTask", []) == "services"


def test_classify_by_api_category() -> None:
    """Fall back to API usage categories when name isn't indicative."""
    assert _classify_to_group("com.app.core.Handler", ["sms_access"]) == "sms"
    assert _classify_to_group("com.app.core.Helper", ["device_admin"]) == "device_admin"


def test_classify_other() -> None:
    """Classes with no indicators go to 'other'."""
    assert _classify_to_group("com.app.core.Utils", []) == "other"


def test_grouper_with_classes() -> None:
    """Full analyzer groups classes correctly."""
    ctx = AnalysisContext()
    ctx.shared["class_filter"] = {
        "classified_classes": {
            "developer": [
                "Lcom/app/network/ApiClient;",
                "Lcom/app/database/UserDao;",
                "Lcom/app/activity/MainActivity;",
                "Lcom/app/receiver/SmsReceiver;",
                "Lcom/app/core/Utils;",
            ]
        },
        "developer_source_paths": [],
    }
    ctx.shared["api_usage"] = {"hits_by_category": {}}

    result = GrouperAnalyzer().analyze(ctx)
    groups = result.evidence["groups"]

    assert isinstance(groups, dict)
    count = result.evidence["group_count"]
    total = result.evidence["total_classified"]
    assert isinstance(count, int)
    assert isinstance(total, int)
    assert count > 0
    assert total == 5


def test_grouper_empty_classes() -> None:
    """Grouper handles empty input gracefully."""
    ctx = AnalysisContext()
    ctx.shared["class_filter"] = {
        "classified_classes": {"developer": []},
        "developer_source_paths": [],
    }
    result = GrouperAnalyzer().analyze(ctx)
    total = result.evidence["total_classified"]
    assert isinstance(total, int)
    assert total == 0
