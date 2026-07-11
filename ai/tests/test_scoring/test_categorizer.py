"""Unit tests for the malware categorizer."""

from __future__ import annotations

from ai.scoring.categorizer import classify


class TestCategoryClassification:
    """Test malware category classification logic."""

    def test_no_signals_returns_unknown(self) -> None:
        primary, secondary = classify([], [])
        assert primary == "unknown"
        assert secondary == []

    def test_overlay_mitre_indicates_banking_trojan(self) -> None:
        """MITRE T1417.002 (overlay) strongly indicates banking trojan."""
        primary, _ = classify([], ["T1417.002"])
        assert primary == "banking_trojan"

    def test_sms_intercept_indicates_banking(self) -> None:
        primary, _ = classify([], ["T1636.004"])
        assert primary in ("banking_trojan", "spyware")

    def test_contact_audio_indicates_spyware(self) -> None:
        """Contact list + audio capture → spyware."""
        primary, _ = classify([], ["T1636.003", "T1429"])
        assert primary == "spyware"

    def test_ransomware_from_mitre(self) -> None:
        """Data encrypted for impact → ransomware."""
        primary, _ = classify([], ["T1486"])
        assert primary == "ransomware"

    def test_dynamic_loading_indicates_dropper(self) -> None:
        primary, _ = classify([], ["T1407", "T1620"])
        assert primary == "dropper"

    def test_finding_types_contribute(self) -> None:
        """Finding types like ioc_match strongly push banking_trojan."""
        primary, _ = classify(["ioc_match", "c2", "obfuscation"], [])
        assert primary == "banking_trojan"

    def test_threat_intel_family_matching(self) -> None:
        """Known banking families get huge votes."""
        primary, _ = classify(
            [],
            [],
            agent_outputs={
                "threat_intel_agent": {
                    "malware_families": [{"family_name": "Anubis"}]
                }
            },
        )
        assert primary == "banking_trojan"

    def test_permission_combo_sms_overlay(self) -> None:
        """SMS + overlay permission combo → banking trojan."""
        primary, _ = classify(
            [],
            [],
            permissions=[
                "android.permission.RECEIVE_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
            ],
        )
        assert primary == "banking_trojan"

    def test_permission_combo_camera_audio_location(self) -> None:
        """Camera + audio + location → spyware."""
        primary, _ = classify(
            [],
            [],
            permissions=[
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION",
            ],
        )
        assert primary == "spyware"

    def test_secondary_categories_returned(self) -> None:
        """Multiple strong signals produce secondary categories."""
        primary, secondary = classify(
            ["c2", "data_exfil", "obfuscation", "control_flow"],
            ["T1417.002", "T1636.004", "T1636.003"],
        )
        assert primary == "banking_trojan"
        # spyware should appear as secondary due to contact/sms signals
        assert len(secondary) >= 1

    def test_meta_categories_excluded(self) -> None:
        """Meta-categories like 'evasion' are excluded from results."""
        primary, secondary = classify([], ["T1027", "T1406"])
        # These map to "evasion" which should be removed
        assert primary == "unknown"
        assert "evasion" not in secondary

    def test_string_family_names_handled(self) -> None:
        """Threat intel families as plain strings work."""
        primary, _ = classify(
            [],
            [],
            agent_outputs={
                "threat_intel_agent": {
                    "malware_families": ["Cerberus", "EventBot"]
                }
            },
        )
        assert primary == "banking_trojan"
