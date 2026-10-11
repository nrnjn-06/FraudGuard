"""
FraudGuard: Unified Comprehensive Test Suite
Validates all scoring, classification, risk matrix, critical signal overrides,
and contribution accounting logic.

Zero legacy references.
"""

import sys
import os

# Ensure backend directory and backend/scoring are in Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scoring"))

from scoring_engine import (
    calculate_ui_safety_score,
    calculate_store_trust_score,
    calculate_fraudguard_scores,
    get_score_level
)
from risk_engine import (
    calculate_overall_risk,
    get_band_level,
    extract_critical_signals
)


def test_store_trust_boundaries():
    print("\n--- 1. Testing Store Trust Boundary Classifications ---")
    boundaries = [
        (0, "LOW"),
        (30, "LOW"),
        (31, "MEDIUM"),
        (75, "MEDIUM"),
        (76, "HIGH"),
        (100, "HIGH")
    ]
    for score, expected_level in boundaries:
        level = get_score_level(score, is_trust=True)
        print(f"Store Trust Score {score} -> Level {level} (Expected: {expected_level})")
        assert level == expected_level, f"Failed for Store Trust {score}: got {level}, expected {expected_level}"
    print("[PASS] Store Trust boundaries verified: 0-30 LOW, 31-75 MEDIUM, 76-100 HIGH.")


def test_ui_safety_boundaries():
    print("\n--- 2. Testing UI Safety Boundary Classifications ---")
    boundaries = [
        (0, "LOW"),
        (30, "LOW"),
        (31, "MEDIUM"),
        (75, "MEDIUM"),
        (76, "HIGH"),
        (100, "HIGH")
    ]
    for score, expected_level in boundaries:
        level = get_score_level(score, is_trust=False)
        print(f"UI Safety Score {score} -> Level {level} (Expected: {expected_level})")
        assert level == expected_level, f"Failed for UI Safety {score}: got {level}, expected {expected_level}"
    print("[PASS] UI Safety boundaries verified: 0-30 LOW, 31-75 MEDIUM, 76-100 HIGH.")


def test_ui_safety_reversal():
    print("\n--- 3. Testing UI Safety Reversal (100 - R) ---")
    # Clean UI (R = 0) -> UI Safety = 100
    score, level, breakdown, _ = calculate_ui_safety_score([], [])
    assert score == 100
    assert level == "HIGH"
    assert breakdown["ui_safety_score"] == 100
    assert breakdown["risk_score"] == 0

    # Rule detections producing R = 50 -> UI Safety = 50
    detections = [
        {"category": "URGENCY", "severity": "low"},      # 15 pts
        {"category": "COUNTDOWN", "severity": "medium"},  # 25 pts
        # Diversity bonus for 2 categories: +10 pts -> Total R = 50
    ]
    score, level, breakdown, _ = calculate_ui_safety_score(detections, ml_results=None)
    assert score == 50, f"Expected 50, got {score}"
    assert level == "MEDIUM"
    assert breakdown["risk_score"] == 50
    assert breakdown["ui_safety_score"] == 50

    # Maximum deceptive patterns (R = 100) -> UI Safety = 0
    detections_max = [
        {"category": "URGENCY", "severity": "high"},
        {"category": "SCARCITY", "severity": "high"},
        {"category": "COUNTDOWN", "severity": "high"},
    ]
    ml_max = [{"prediction": "DARK_PATTERN", "confidence": 1.0, "dark_pattern_probability": 1.0}]
    score, level, breakdown, _ = calculate_ui_safety_score(detections_max, ml_max)
    assert score == 0, f"Expected 0, got {score}"
    assert level == "LOW"
    assert breakdown["ui_safety_score"] == 0

    print("[PASS] UI Safety reversal (100 - R) verified: R=0 -> 100, R=50 -> 50, R=100 -> 0.")


def test_overall_risk_matrix():
    print("\n--- 4. Testing All 9 Combinations in Overall Risk Matrix ---")
    # Format: (trust_score, trust_lvl, ui_score, ui_lvl, expected_risk, expected_case)
    matrix_cases = [
        # LOW TRUST (0-30): Base Risk is HIGH RISK
        (20, "LOW", 20, "LOW", "HIGH", "LOW_TRUST_LOW_UI_SAFETY"),
        (20, "LOW", 50, "MEDIUM", "HIGH", "LOW_TRUST_MED_UI_SAFETY"),
        (20, "LOW", 90, "HIGH", "MEDIUM", "LOW_TRUST_HIGH_UI_SAFETY"),

        # MEDIUM TRUST (31-75): Base Risk is MEDIUM RISK
        (50, "MEDIUM", 20, "LOW", "HIGH", "MED_TRUST_LOW_UI_SAFETY"),
        (50, "MEDIUM", 50, "MEDIUM", "MEDIUM", "MED_TRUST_MED_UI_SAFETY"),
        (50, "MEDIUM", 90, "HIGH", "MEDIUM", "MED_TRUST_HIGH_UI_SAFETY"),

        # HIGH TRUST (76-100): Base Risk is LOW RISK
        (90, "HIGH", 20, "LOW", "MEDIUM", "HIGH_TRUST_LOW_UI_SAFETY"),
        (90, "HIGH", 50, "MEDIUM", "LOW", "HIGH_TRUST_MED_UI_SAFETY"),
        (90, "HIGH", 90, "HIGH", "LOW", "HIGH_TRUST_HIGH_UI_SAFETY"),
    ]

    for trust_score, trust_lvl, ui_score, ui_lvl, expected_risk, expected_case in matrix_cases:
        res = calculate_overall_risk(
            store_trust_score=trust_score,
            store_trust_level=trust_lvl,
            ui_safety_score=ui_score,
            ui_safety_level=ui_lvl,
            detections=[],
            ml_results=[],
            domain_intelligence={}
        )
        actual_risk = res["overall_risk"]
        actual_case = res["decision_matrix_case"]
        print(f"Trust {trust_score} ({trust_lvl}) + UI Safety {ui_score} ({ui_lvl}) -> Risk: {actual_risk} [Case: {actual_case}]")
        assert actual_risk == expected_risk, f"Matrix mismatch for Trust={trust_lvl}, UI={ui_lvl}: expected {expected_risk}, got {actual_risk}"
        assert actual_case == expected_case, f"Case mismatch: expected {expected_case}, got {actual_case}"

    print("[PASS] All 9 combinations in the Store Trust-priority risk matrix verified.")


def test_critical_signal_overrides():
    print("\n--- 5. Testing Critical Signal Overrides to HIGH RISK ---")
    # Base setup: Highly trusted domain (100) + High UI Safety (100) which would normally be LOW RISK
    base_trust = 100
    base_trust_lvl = "HIGH"
    base_ui = 100
    base_ui_lvl = "HIGH"

    # 1. CRITICAL_NEW_DOMAIN (< 30 days)
    intel_new_domain = {
        "domain": "test-brand.com",
        "whois": {"domain_age_days": 14},
        "domain_characteristics": {"domain_age_days": 14}
    }
    res = calculate_overall_risk(
        store_trust_score=base_trust,
        store_trust_level=base_trust_lvl,
        ui_safety_score=base_ui,
        ui_safety_level=base_ui_lvl,
        detections=[],
        ml_results=[],
        domain_intelligence=intel_new_domain
    )
    print(f"Critical New Domain (< 30 days) -> Overall Risk: {res['overall_risk']}")
    assert res["overall_risk"] == "HIGH"
    assert any("under 30 days" in s.lower() or "newly registered" in s.lower() for s in res["critical_signals"])
    assert res["decision_matrix_case"].endswith("_ESCALATED_CRITICAL")

    # 2. CRITICAL_INVALID_SSL
    intel_bad_ssl = {
        "domain": "test-brand.com",
        "ssl": {"available": True, "valid": False, "hostname_verified": False}
    }
    res = calculate_overall_risk(
        store_trust_score=base_trust,
        store_trust_level=base_trust_lvl,
        ui_safety_score=base_ui,
        ui_safety_level=base_ui_lvl,
        detections=[],
        ml_results=[],
        domain_intelligence=intel_bad_ssl
    )
    print(f"Critical Invalid SSL -> Overall Risk: {res['overall_risk']}")
    assert res["overall_risk"] == "HIGH"
    assert any("invalid" in s.lower() or "ssl" in s.lower() for s in res["critical_signals"])
    assert res["decision_matrix_case"].endswith("_ESCALATED_CRITICAL")

    # 3. CRITICAL_RECURRING_PAYMENT
    detections_recurring = [
        {"category": "RECURRING_PAYMENT", "severity": "high", "message": "Pre-selected recurring monthly protection"}
    ]
    res = calculate_overall_risk(
        store_trust_score=base_trust,
        store_trust_level=base_trust_lvl,
        ui_safety_score=base_ui,
        ui_safety_level=base_ui_lvl,
        detections=detections_recurring,
        ml_results=[],
        domain_intelligence={}
    )
    print(f"Critical Recurring Payment -> Overall Risk: {res['overall_risk']}")
    assert res["overall_risk"] == "HIGH"
    assert any("recurring" in s.lower() or "subscription" in s.lower() for s in res["critical_signals"])
    assert res["decision_matrix_case"].endswith("_ESCALATED_CRITICAL")

    # 4. CRITICAL_PUNYCODE_HOMOGRAPH
    intel_punycode = {
        "domain": "xn--app-8oa.com",
        "domain_characteristics": {"punycode": True, "suspicious_structural_flags": ["punycode_homograph"]}
    }
    res = calculate_overall_risk(
        store_trust_score=base_trust,
        store_trust_level=base_trust_lvl,
        ui_safety_score=base_ui,
        ui_safety_level=base_ui_lvl,
        detections=[],
        ml_results=[],
        domain_intelligence=intel_punycode
    )
    print(f"Critical Punycode Homograph -> Overall Risk: {res['overall_risk']}")
    assert res["overall_risk"] == "HIGH"
    assert any("punycode" in s.lower() or "homograph" in s.lower() for s in res["critical_signals"])
    assert res["decision_matrix_case"].endswith("_ESCALATED_CRITICAL")

    # 5. CRITICAL_MULTIPLE_STRUCTURAL_FLAGS (>= 2 flags)
    intel_multi_flags = {
        "domain": "cheap-login-verify-account.top",
        "domain_characteristics": {
            "punycode": False,
            "suspicious_structural_flags": ["excessive_hyphens", "numeric_heavy"]
        }
    }
    res = calculate_overall_risk(
        store_trust_score=base_trust,
        store_trust_level=base_trust_lvl,
        ui_safety_score=base_ui,
        ui_safety_level=base_ui_lvl,
        detections=[],
        ml_results=[],
        domain_intelligence=intel_multi_flags
    )
    print(f"Critical Multiple Structural Flags -> Overall Risk: {res['overall_risk']}")
    assert res["overall_risk"] == "HIGH"
    assert any("structural" in s.lower() or "multiple" in s.lower() for s in res["critical_signals"])
    assert res["decision_matrix_case"].endswith("_ESCALATED_CRITICAL")

    print("[PASS] All 5 critical signals successfully escalate Overall Risk to HIGH.")


def test_contribution_accounting():
    print("\n--- 6. Testing Exact Contribution Accounting ---")
    dom_intel = {
        "domain": "legit-store.com",
        "whois": {
            "available": True,
            "registrar": "Example Registrar LLC",
            "domain_age_days": 800,  # 2-5 years -> 35 pts
            "name_servers": ["ns1.example.com", "ns2.example.com"]  # 20 pts
        },
        "ssl": {
            "available": True,
            "valid": True,
            "hostname_verified": True  # 20 pts
        },
        "domain_characteristics": {
            "suspicious_structural_flags": []  # Clean -> 20 pts
        }
    }
    # Expected Store Trust = 35 + 20 + 20 + 20 = 95
    trust_score, trust_lvl, trust_breakdown, _ = calculate_store_trust_score(dom_intel)
    assert trust_score == 95, f"Expected 95, got {trust_score}"
    assert trust_lvl == "HIGH"
    trust_contrib_sum = sum(c["contribution_points"] for c in trust_breakdown["contributions"])
    print(f"Store Trust Score: {trust_score}, Contrib Sum: {trust_contrib_sum}")
    assert trust_contrib_sum == trust_score, f"Trust contrib sum {trust_contrib_sum} != {trust_score}"

    # UI Safety Contributions
    detections = [
        {"category": "URGENCY", "severity": "low"},
        {"category": "SCARCITY", "severity": "medium"}
    ]
    ml = [{"prediction": "DARK_PATTERN", "confidence": 0.85, "dark_pattern_probability": 0.85}]
    ui_score, ui_lvl, ui_breakdown, _ = calculate_ui_safety_score(detections, ml)
    ui_contrib_sum = sum(c["contribution_points"] for c in ui_breakdown["contributions"])
    print(f"UI Safety Score: {ui_score}, Contrib Sum: {ui_contrib_sum}")
    assert ui_contrib_sum == ui_score, f"UI contrib sum {ui_contrib_sum} != {ui_score}"

    print("[PASS] Contribution accounting verified: sum(contributions) strictly equals total score.")


def main():
    print("==================================================")
    print("FRAUDGUARD COMPREHENSIVE INTEGRATION SUITE")
    print("==================================================")
    test_store_trust_boundaries()
    test_ui_safety_boundaries()
    test_ui_safety_reversal()
    test_overall_risk_matrix()
    test_critical_signal_overrides()
    test_contribution_accounting()
    print("\n==================================================")
    print("ALL TESTS PASSED SUCCESSFULLY!")
    print("==================================================")


if __name__ == "__main__":
    main()
