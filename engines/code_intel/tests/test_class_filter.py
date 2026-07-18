"""Tests for the class filter analyzer."""

from __future__ import annotations

from sephela_code_intel.analyzers.class_filter import ClassFilterAnalyzer, classify_class
from sephela_code_intel.base import AnalysisContext


def test_framework_classes_classified() -> None:
    """Android SDK and Jetpack packages are classified as framework."""
    assert classify_class("Landroid/app/Activity;") == "framework"
    assert classify_class("Landroidx/fragment/app/Fragment;") == "framework"
    assert classify_class("Ljava/lang/String;") == "framework"
    assert classify_class("Lkotlin/Pair;") == "framework"


def test_third_party_classes_classified() -> None:
    """Common libraries are classified as third_party."""
    assert classify_class("Lcom/google/gson/Gson;") == "third_party"
    assert classify_class("Lokhttp3/OkHttpClient;") == "third_party"
    assert classify_class("Lcom/squareup/retrofit2/Retrofit;") == "third_party"
    assert classify_class("Lcom/bumptech/glide/Glide;") == "third_party"


def test_generated_code_classified() -> None:
    """Generated code patterns are detected."""
    assert classify_class("Lcom/example/R$layout;") == "generated"
    assert classify_class("Lcom/example/BuildConfig;") == "generated"
    assert classify_class("Lcom/example/DaggerAppComponent;") == "generated"
    assert classify_class("Lcom/example/databinding/ActivityMainBinding;") == "generated"


def test_developer_code_classified() -> None:
    """Anything not matching known patterns is classified as developer."""
    assert classify_class("Lcom/malware/app/MainActivity;") == "developer"
    assert classify_class("Lcom/banking/trojan/SmsHijacker;") == "developer"
    assert classify_class("Lorg/custom/tool/Helper;") == "developer"


def test_java_dot_notation() -> None:
    """Classification works with Java dot notation too."""
    assert classify_class("android.app.Activity") == "framework"
    assert classify_class("com.google.gson.Gson") == "third_party"
    assert classify_class("com.malware.app.Main") == "developer"


def test_analyzer_with_smali_classes() -> None:
    """The full analyzer classifies from the smali class list."""
    ctx = AnalysisContext(
        static_evidence={
            "smali": {
                "classes": [
                    "Lcom/malware/app/Main;",
                    "Landroid/app/Activity;",
                    "Lcom/google/gson/Gson;",
                    "Lcom/example/R$layout;",
                ],
            }
        }
    )
    result = ClassFilterAnalyzer().analyze(ctx)
    stats = result.evidence["stats"]
    assert isinstance(stats, dict)

    assert stats["total_classes"] == 4
    assert stats["developer_count"] == 1
    assert stats["framework_count"] == 1
    assert stats["third_party_count"] == 1
    assert stats["generated_count"] == 1
    assert stats["developer_ratio"] == 0.25


def test_analyzer_empty_classes() -> None:
    """Analyzer handles empty class list gracefully."""
    ctx = AnalysisContext(static_evidence={"smali": {"classes": []}})
    result = ClassFilterAnalyzer().analyze(ctx)
    stats = result.evidence["stats"]
    assert isinstance(stats, dict)
    assert stats["total_classes"] == 0
