"""
FraudGuard Scoring & Risk Engine Package
Independent UI Safety and Store Trust Scoring Modules
"""

from .scoring_engine import (
    calculate_ui_safety_score,
    calculate_deceptive_ui_score,
    calculate_store_trust_score,
    calculate_fraudguard_scores,
    get_score_level,
)
from .risk_engine import calculate_overall_risk

__all__ = [
    "calculate_ui_safety_score",
    "calculate_deceptive_ui_score",
    "calculate_store_trust_score",
    "calculate_fraudguard_scores",
    "get_score_level",
    "calculate_overall_risk",
]
