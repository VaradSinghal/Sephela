"""Risk Scoring Engine — deterministic, explainable APK threat scoring.

Public API:
    from ai.scoring import RiskScoringEngine
    engine = RiskScoringEngine()
    result = engine.score(findings, agent_outputs)
"""

from ai.scoring.engine import RiskScoringEngine

__all__ = ["RiskScoringEngine"]
