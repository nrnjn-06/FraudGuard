"""
FraudGuard: Automated Scoring Engine Test Suite
Tests all core scoring scenarios:
- Test 1: Clean / Trusted Website
- Test 2: Trusted Website with Deceptive UI (DECEPTIVE UI != FRAUD)
- Test 3: Suspicious / New Domain without Deceptive UI
- Test 4: Multiple Suspicious Signals
- Test 5: Missing Domain Data (INSUFFICIENT_DATA handling)
- Test 6: No ML Result (Graceful rule-based fallback)
- Test 7: Contribution Accounting Invariance
"""

import sys
from scoring_engine import (
    calculate_ui_safety_score,
    calculate_store_trust_score,
    calculate_fraudguard_scores,
    get_score_level
)


def run_tests():
    print("==================================================")
    print("FRAUDGUARD SCORING ENGINE TEST SUITE")
    print("==================================================")

    # --------------------------------------------------
    # TEST 1 — CLEAN / TRUSTED WEBSITE
    # --------------------------------------------------
    print("\n--- TEST 1: CLEAN / TRUSTED WEBSITE ---")
    dom_intel_clean = {
        "domain": "nike.com",
        "registered_domain": "nike.com",
        "whois": {
            "available": True,
            "registrar": "MarkMonitor, Inc.",
            "domain_age_days": 9500,
            "name_servers": ["ns1.markmonitor.com", "ns2.markmonitor.com"]
        },
        "ssl": {
            "available": True,
            "valid": True,
            "hostname_verified": True,
            "tls_version": "TLSv1.3",
            "issuer": "DigiCert Inc"
        },
        "domain_characteristics": {
            "is_young_domain": False,
            "domain_age_days": 9500,
            "punycode": False,
            "excessive_hyphens": False,
            "numeric_heavy": False,
            "long_hostname": False,
            "subdomain_count": 0
        }
    }
    result_1 = calculate_fraudguard_scores(
        detections=[],
        ml_results=[],
        domain_intelligence=dom_intel_clean
    )
    print(f"UI Safety Score:   {result_1['ui_safety_score']} ({result_1['ui_safety_level']})")
    print(f"Store Trust Score: {result_1['store_trust_score']} ({result_1['store_trust_level']})")

    assert result_1["ui_safety_score"] >= 76, f"Expected HIGH UI safety score, got {result_1['ui_safety_score']}"
    assert result_1["ui_safety_level"] == "HIGH"
    assert result_1["store_trust_score"] >= 76, f"Expected HIGH store trust score, got {result_1['store_trust_score']}"
    assert result_1["store_trust_level"] == "HIGH"
    print("[PASS] Test 1 passed: Clean website has HIGH UI safety and HIGH store trust.")

    # --------------------------------------------------
    # TEST 2 — TRUSTED WEBSITE WITH DECEPTIVE UI
    # Demonstrates: DECEPTIVE UI != FRAUD
    # --------------------------------------------------
    print("\n--- TEST 2: TRUSTED WEBSITE WITH DECEPTIVE UI (DECEPTIVE UI != FRAUD) ---")
    detections_aggressive = [
        {"category": "URGENCY", "severity": "low", "message": "Hurry, deal ends in 2 hours!"},
        {"category": "SCARCITY", "severity": "low", "message": "Only 1 item left in stock!"},
        {"category": "COUNTDOWN", "severity": "medium", "message": "Sale ends in: 00:15:30"},
        {"category": "RECURRING_PAYMENT", "severity": "high", "message": "Add monthly protection $9.99/mo"}
    ]
    ml_results_high = [
        {"prediction": "DARK_PATTERN", "confidence": 0.985, "dark_pattern_probability": 0.985}
    ]
    result_2 = calculate_fraudguard_scores(
        detections=detections_aggressive,
        ml_results=ml_results_high,
        domain_intelligence=dom_intel_clean  # Legitimate, longstanding domain
    )
    print(f"UI Safety Score:   {result_2['ui_safety_score']} ({result_2['ui_safety_level']})")
    print(f"Store Trust Score: {result_2['store_trust_score']} ({result_2['store_trust_level']})")

    assert result_2["ui_safety_score"] <= 30, f"Expected LOW UI safety score, got {result_2['ui_safety_score']}"
    assert result_2["ui_safety_level"] == "LOW"
    assert result_2["store_trust_score"] >= 76, f"Expected HIGH store trust score, got {result_2['store_trust_score']}"
    assert result_2["store_trust_level"] == "HIGH"
    print("[PASS] Test 2 passed: Website has LOW UI safety but HIGH store trust. DECEPTIVE UI != FRAUD!")

    # --------------------------------------------------
    # TEST 3 — SUSPICIOUS / NEW DOMAIN WITHOUT DECEPTIVE UI
    # --------------------------------------------------
    print("\n--- TEST 3: SUSPICIOUS / NEW DOMAIN WITHOUT DECEPTIVE UI ---")
    dom_intel_suspicious = {
        "domain": "cheap-discount-store-88392.top",
        "registered_domain": "cheap-discount-store-88392.top",
        "whois": {
            "available": True,
            "registrar": "CheapNames LLC",
            "domain_age_days": 12,  # Only 12 days old!
            "name_servers": ["ns1.cheapnames.com"]
        },
        "ssl": {
            "available": True,
            "valid": True,
            "hostname_verified": True,
            "tls_version": "TLSv1.2",
            "issuer": "Let's Encrypt"
        },
        "domain_characteristics": {
            "is_young_domain": True,
            "domain_age_days": 12,
            "punycode": False,
            "excessive_hyphens": True,  # 3 hyphens
            "numeric_heavy": True,      # digits > 30%
            "long_hostname": True,
            "subdomain_count": 0
        }
    }
    result_3 = calculate_fraudguard_scores(
        detections=[],
        ml_results=[],
        domain_intelligence=dom_intel_suspicious
    )
    print(f"UI Safety Score:   {result_3['ui_safety_score']} ({result_3['ui_safety_level']})")
    print(f"Store Trust Score: {result_3['store_trust_score']} ({result_3['store_trust_level']})")

    assert result_3["ui_safety_score"] >= 76, f"Expected HIGH UI safety score, got {result_3['ui_safety_score']}"
    assert result_3["ui_safety_level"] == "HIGH"
    assert result_3["store_trust_score"] <= 35, f"Expected low store trust score, got {result_3['store_trust_score']}"
    print("[PASS] Test 3 passed: Suspicious new domain has low store trust despite clean UI.")

    # --------------------------------------------------
    # TEST 4 — MULTIPLE SUSPICIOUS SIGNALS
    # --------------------------------------------------
    print("\n--- TEST 4: MULTIPLE SUSPICIOUS SIGNALS (NEW DOMAIN + INVALID SSL + DECEPTIVE UI) ---")
    dom_intel_hostile = {
        "domain": "pay-auth-login-verify-account.tk",
        "registered_domain": "pay-auth-login-verify-account.tk",
        "whois": {
            "available": True,
            "registrar": "Unknown",
            "domain_age_days": 5,
            "name_servers": []
        },
        "ssl": {
            "available": True,
            "valid": False,  # Untrusted or expired
            "hostname_verified": False,
            "error": "Self-signed certificate untrusted"
        },
        "domain_characteristics": {
            "is_young_domain": True,
            "domain_age_days": 5,
            "punycode": False,
            "excessive_hyphens": True,
            "numeric_heavy": False,
            "long_hostname": True,
            "subdomain_count": 0
        }
    }
    result_4 = calculate_fraudguard_scores(
        detections=detections_aggressive,
        ml_results=ml_results_high,
        domain_intelligence=dom_intel_hostile
    )
    print(f"UI Safety Score:   {result_4['ui_safety_score']} ({result_4['ui_safety_level']})")
    print(f"Store Trust Score: {result_4['store_trust_score']} ({result_4['store_trust_level']})")

    assert result_4["ui_safety_score"] <= 30, f"Expected LOW UI safety score, got {result_4['ui_safety_score']}"
    assert result_4["ui_safety_level"] == "LOW"
    assert result_4["store_trust_score"] <= 30, f"Expected LOW store trust score, got {result_4['store_trust_score']}"
    assert result_4["store_trust_level"] == "LOW"
    print("[PASS] Test 4 passed: Highly suspicious site has LOW UI safety and LOW store trust.")

    # --------------------------------------------------
    # TEST 5 — MISSING DOMAIN DATA
    # --------------------------------------------------
    print("\n--- TEST 5: MISSING DOMAIN DATA (INSUFFICIENT DATA HANDLING) ---")
    dom_intel_missing = {
        "domain": "unresolved-store.internal",
        "whois": {"available": False, "error": "Lookup failed"},
        "ssl": {"available": False, "error": "Connection refused"},
        "domain_characteristics": {}
    }
    result_5 = calculate_fraudguard_scores(
        detections=[],
        ml_results=[],
        domain_intelligence=dom_intel_missing
    )
    print(f"Store Trust Score: {result_5['store_trust_score']}, Level: {result_5['store_trust_level']}")
    assert result_5["store_trust_score"] is None, f"Expected None score on missing data, got {result_5['store_trust_score']}"
    assert result_5["store_trust_level"] == "INSUFFICIENT_DATA"
    print("[PASS] Test 5 passed: System cleanly marks store trust as INSUFFICIENT_DATA rather than assigning 0 or 100.")

    # --------------------------------------------------
    # TEST 6 — NO ML RESULT (GRACEFUL FALLBACK)
    # --------------------------------------------------
    print("\n--- TEST 6: NO ML RESULT (RULE-BASED GRACEFUL FALLBACK) ---")
    detections_rules_only = [
        {"category": "URGENCY", "severity": "low", "message": "Act fast!"},
        {"category": "COUNTDOWN", "severity": "medium", "message": "Sale ends in 5 minutes"}
    ]
    # ML is completely omitted / null
    result_6 = calculate_fraudguard_scores(
        detections=detections_rules_only,
        ml_results=None,
        domain_intelligence=dom_intel_clean
    )
    print(f"UI Safety Score: {result_6['ui_safety_score']} ({result_6['ui_safety_level']})")
    assert result_6["ui_safety_breakdown"]["ml_available"] is False
    assert result_6["ui_safety_score"] == 50  # 100 - (15 + 25 + 10) = 50
    assert result_6["ui_safety_level"] == "MEDIUM"
    print("[PASS] Test 6 passed: UI Safety score accurately calculates from rules when ML is unavailable.")

    # --------------------------------------------------
    # TEST 7 — CONTRIBUTION ACCOUNTING INVARIANCE
    # --------------------------------------------------
    print("\n--- TEST 7: CONTRIBUTION ACCOUNTING INVARIANCE ---")
    ui_contrib_sum = sum(c["contribution_points"] for c in result_2["ui_safety_contributions"])
    assert ui_contrib_sum == result_2["ui_safety_score"], f"UI contrib sum {ui_contrib_sum} != {result_2['ui_safety_score']}"

    trust_contrib_sum = sum(c["contribution_points"] for c in result_1["store_trust_contributions"])
    assert trust_contrib_sum == result_1["store_trust_score"], f"Trust contrib sum {trust_contrib_sum} != {result_1['store_trust_score']}"
    print(f"[PASS] Test 7 passed: UI Safety contrib sum ({ui_contrib_sum}) == score ({result_2['ui_safety_score']}) and Trust contrib sum ({trust_contrib_sum}) == score ({result_1['store_trust_score']}).")

    print("\n==================================================")
    print("ALL SCORING ENGINE SCENARIOS PASSED!")
    print("==================================================")


if __name__ == "__main__":
    run_tests()
