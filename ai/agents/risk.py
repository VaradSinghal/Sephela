"""Risk Scoring Agent — wraps the deterministic scoring engine with LLM narrative.

Phase 7 placed the scoring math directly in this agent. Phase 8 extracted it
into ``ai.scoring.engine.RiskScoringEngine``. This agent now:

1. Calls the scoring engine for the deterministic baseline.
2. Asks the LLM to narrate/contextualize the result (optional).
3. Emits a ``RiskAnalysis`` Pydantic model.

The separation ensures the score itself is reproducible (no LLM randomness
in the math), while the LLM adds a human-readable risk narrative and may
flag novel combinations the engine's rules don't cover.
"""

from __future__ import annotations

import json
from typing import Any

from ai.agents.base import BaseAgent, AgentConfig, AgentResult
from ai.schemas.base import Finding, Severity, Confidence
from ai.schemas.risk import RiskAnalysis, RiskFactor, RiskBreakdown, RiskTier
from ai.scoring.engine import RiskScoringEngine


# Singleton engine instance — thread-safe (it's stateless after __init__).
_ENGINE = RiskScoringEngine()


class RiskAgent(BaseAgent[RiskAnalysis]):
    """Computes explainable risk score from all agent findings."""

    def __init__(self, llm_client: Any = None):
        config = AgentConfig(
            name="risk_agent",
            model="claude-3-5-sonnet-20241022",
            temperature=0.1,
            max_tokens=4096,
            output_schema=RiskAnalysis,
            system_prompt=self._get_system_prompt(),
        )
        super().__init__(config, llm_client)

    def _get_system_prompt(self) -> str:
        return """You are a senior risk analyst specializing in Android malware risk scoring.
Your task is to review the deterministic risk assessment and provide:
1. A concise risk narrative explaining WHY this APK received this score
2. Recommended actions for the security team
3. Any novel threat combinations the deterministic model may have missed

The deterministic score has already been computed — do NOT recalculate it.
Focus on contextualizing the findings and explaining their implications.

Output must conform to RiskAnalysis schema."""

    def build_prompt(self, evidence: dict[str, Any], context: dict[str, Any]) -> str:
        # Collect all findings from previous agents
        all_findings: list[Any] = []
        agent_outputs: dict[str, Any] = {}

        for agent_name in [
            "manifest_agent", "permission_agent", "code_agent",
            "api_agent", "network_agent", "threat_intel_agent",
        ]:
            findings_key = f"{agent_name}_findings"
            output_key = f"{agent_name}_output"
            if findings_key in context:
                all_findings.extend(context[findings_key])
            if output_key in context:
                agent_outputs[agent_name] = context[output_key]

        # Also include any findings directly in evidence
        if "findings" in evidence:
            all_findings.extend(evidence["findings"])

        # Extract permissions from evidence if available
        permissions: list[str] | None = None
        if "permissions" in evidence:
            perms = evidence["permissions"]
            if isinstance(perms, dict):
                permissions = perms.get("permissions", [])
            elif isinstance(perms, list):
                permissions = perms

        # Run the deterministic scoring engine
        scoring_result = _ENGINE.score(all_findings, agent_outputs, permissions)

        # Build prompt with the deterministic result
        domain_summary = "\n".join(
            f"  - {ds.domain}: {ds.raw_score:.1f} (weight {ds.weight}, "
            f"contributes {ds.weighted_score:.1f}, {ds.finding_count} findings)"
            for ds in scoring_result.domain_scores
        )

        synergy_summary = "None"
        if scoring_result.synergy_bonuses:
            synergy_summary = "\n".join(
                f"  - {sb.name} (+{sb.bonus} pts): {sb.description}"
                for sb in scoring_result.synergy_bonuses
            )

        prompt = f"""Review the deterministic risk assessment and provide narrative context.

=== DETERMINISTIC SCORE ===
Base Score: {scoring_result.base_score}
Synergy Bonus: {scoring_result.synergy_bonus}
Final Score: {scoring_result.final_score}
Tier: {scoring_result.tier.value}
Confidence: {scoring_result.confidence}
Category: {scoring_result.primary_category}
Secondary: {scoring_result.secondary_categories}

=== DOMAIN BREAKDOWN ===
{domain_summary}

=== SYNERGY RULES FIRED ===
{synergy_summary}

=== KEY FINDINGS ===
{chr(10).join(scoring_result.key_findings)}

=== MITRE ATT&CK ===
{', '.join(scoring_result.mitre_techniques)}

=== OWASP Mobile ===
{', '.join(scoring_result.owasp_categories)}

=== ALL FINDINGS ({len(all_findings)} total) ===
{json.dumps([_finding_summary(f) for f in all_findings[:50]], indent=2)}

Provide a RiskAnalysis with:
1. Use the deterministic score ({scoring_result.final_score}) as-is
2. Add a human-readable risk narrative
3. List recommended actions
4. Flag any novel patterns the rules may have missed"""

        return prompt

    def parse_output(self, raw_output: str) -> RiskAnalysis:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            import re
            match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_output, re.DOTALL)
            if match:
                data = json.loads(match.group(1))
            else:
                raise ValueError("Could not parse agent output as JSON")

        return RiskAnalysis(**data)

    def extract_findings(self, output: RiskAnalysis) -> list[Finding]:
        return []


def _finding_summary(f: Any) -> dict[str, str]:
    """Extract a compact summary from a finding for prompt inclusion."""
    if isinstance(f, dict):
        return {
            "type": str(f.get("type", "")),
            "severity": str(f.get("severity", "")),
            "title": str(f.get("title", ""))[:100],
        }
    return {
        "type": str(getattr(f, "type", "")),
        "severity": str(getattr(f, "severity", "")),
        "title": str(getattr(f, "title", ""))[:100],
    }