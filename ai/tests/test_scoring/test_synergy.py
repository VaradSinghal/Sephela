"""Unit tests for synergy rules evaluation."""

from __future__ import annotations

from ai.scoring.synergy import SYNERGY_RULES, evaluate_synergy


class TestSynergyEvaluation:
    """Test the synergy rule matching logic."""

    def test_no_signals_fires_no_rules(self) -> None:
        """Empty signal sets fire no synergy rules."""
        results = evaluate_synergy(set(), set(), set())
        matched = [r for r, m in results if m]
        assert len(matched) == 0

    def test_overlay_plus_sms_fires_syn001(self) -> None:
        """SYN-001: Overlay + SMS Intercept."""
        results = evaluate_synergy(
            active_domains=set(),
            active_types=set(),
            active_mitre={"T1417.002", "T1636.004"},
        )
        fired = {r.rule_id for r, m in results if m}
        assert "SYN-001" in fired

    def test_full_takeover_fires_syn002(self) -> None:
        """SYN-002: Accessibility + Overlay + Device Admin."""
        results = evaluate_synergy(
            active_domains=set(),
            active_types=set(),
            active_mitre={"T1417.001", "T1417.002", "T1626"},
        )
        fired = {r.rule_id for r, m in results if m}
        assert "SYN-002" in fired

    def test_dropper_pattern_fires_syn003(self) -> None:
        """SYN-003: Dynamic Loading + Reflection + Network."""
        results = evaluate_synergy(
            active_domains={"network"},
            active_types=set(),
            active_mitre={"T1407", "T1620"},
        )
        fired = {r.rule_id for r, m in results if m}
        assert "SYN-003" in fired

    def test_spyware_pattern_fires_syn004(self) -> None:
        """SYN-004: SMS + Contacts + Network Exfil."""
        results = evaluate_synergy(
            active_domains={"network"},
            active_types=set(),
            active_mitre={"T1636.004", "T1636.003"},
        )
        fired = {r.rule_id for r, m in results if m}
        assert "SYN-004" in fired

    def test_evasion_stack_fires_syn005(self) -> None:
        """SYN-005: Obfuscation + Anti-Analysis + Native Code."""
        results = evaluate_synergy(
            active_domains=set(),
            active_types={"obfuscation", "anti_analysis", "native_code"},
            active_mitre=set(),
        )
        fired = {r.rule_id for r, m in results if m}
        assert "SYN-005" in fired

    def test_cleartext_debuggable_fires_syn007(self) -> None:
        """SYN-007: Cleartext Traffic + Debuggable."""
        results = evaluate_synergy(
            active_domains=set(),
            active_types={"cleartext", "debuggable"},
            active_mitre=set(),
        )
        fired = {r.rule_id for r, m in results if m}
        assert "SYN-007" in fired

    def test_threat_intel_plus_permissions_fires_syn008(self) -> None:
        """SYN-008: TI match + High Permissions."""
        results = evaluate_synergy(
            active_domains={"threat_intel", "permissions"},
            active_types=set(),
            active_mitre=set(),
        )
        fired = {r.rule_id for r, m in results if m}
        assert "SYN-008" in fired

    def test_partial_match_does_not_fire(self) -> None:
        """A rule doesn't fire if only some required signals are present."""
        # SYN-001 needs T1417.002 AND T1636.004
        results = evaluate_synergy(
            active_domains=set(),
            active_types=set(),
            active_mitre={"T1417.002"},  # only one of two
        )
        fired = {r.rule_id for r, m in results if m}
        assert "SYN-001" not in fired

    def test_multiple_rules_can_fire(self) -> None:
        """Multiple rules can fire simultaneously if their signals overlap."""
        results = evaluate_synergy(
            active_domains={"network", "permissions", "threat_intel"},
            active_types={"obfuscation", "anti_analysis", "native_code"},
            active_mitre={"T1417.001", "T1417.002", "T1626", "T1636.004", "T1636.003"},
        )
        fired = {r.rule_id for r, m in results if m}
        # Should fire SYN-001, SYN-002, SYN-004, SYN-005, SYN-008, SYN-010
        assert len(fired) >= 4

    def test_all_rules_have_unique_ids(self) -> None:
        """Every synergy rule has a unique rule_id."""
        ids = [r.rule_id for r in SYNERGY_RULES]
        assert len(ids) == len(set(ids))

    def test_all_rules_have_positive_bonus(self) -> None:
        """Every synergy rule adds a positive bonus."""
        for rule in SYNERGY_RULES:
            assert rule.bonus > 0, f"Rule {rule.rule_id} has non-positive bonus"

    def test_all_rules_have_required_signals(self) -> None:
        """Every synergy rule has at least 2 required signals."""
        for rule in SYNERGY_RULES:
            assert len(rule.required_signals) >= 2, (
                f"Rule {rule.rule_id} needs at least 2 signals, "
                f"has {len(rule.required_signals)}"
            )
