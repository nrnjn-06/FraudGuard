"""
FraudGuard: Page Intelligence & Scoring Engine
Provides independent, transparent, evidence-based calculation of:
1. UI Safety Score (0 - 100) — Higher is safer
2. Store Trust Score (0 - 100) — Higher is safer

CORE ARCHITECTURAL PRINCIPLE:
    DECEPTIVE UI != FRAUD
    A legitimate merchant may use promotional urgency or scarcity tactics.
    Conversely, an unestablished phishing storefront may display clean, calm UI.
    Therefore, the UI Safety Score and Store Trust Score are calculated
    completely independently and are NEVER simply averaged.

TERMINOLOGY:
    - "UI safety evidence"
    - "store trust evidence"
    - "risk indicator"
"""

from typing import Dict, Any, List, Optional, Tuple


# Score Band Thresholds — Identical for Store Trust and UI Safety
SCORE_LOW_MAX = 30
SCORE_MED_MAX = 75
# Ranges:
# 0 - 30:   LOW (LOW TRUST / LOW UI SAFETY)
# 31 - 75:  MEDIUM (MEDIUM TRUST / MEDIUM UI SAFETY)
# 76 - 100: HIGH (HIGH TRUST / HIGH UI SAFETY)

STORE_TRUST_LOW_MAX = 30
STORE_TRUST_MED_MAX = 75
UI_SAFETY_LOW_MAX = 30
UI_SAFETY_MED_MAX = 75


def get_score_level(score: Optional[int], is_trust: bool = False) -> str:
    """
    Maps a 0-100 score to its evidence-based band.
    Both Store Trust and UI Safety use identical boundaries:
        0 - 30:   LOW
        31 - 75:  MEDIUM
        76 - 100: HIGH
    Returns 'INSUFFICIENT_DATA' if score is None.
    """
    if score is None:
        return "INSUFFICIENT_DATA"

    bounded = max(0, min(100, int(score)))
    if bounded <= SCORE_LOW_MAX:
        return "LOW"
    elif bounded <= SCORE_MED_MAX:
        return "MEDIUM"
    else:
        return "HIGH"


def calculate_ui_safety_score(
    detections: Optional[List[Dict[str, Any]]] = None,
    ml_results: Optional[List[Dict[str, Any]]] = None
) -> Tuple[int, str, Dict[str, Any], List[Dict[str, Any]]]:
    """
    Calculates the UI Safety Score (0 - 100) based on:
    - Detection count and severities (high, medium, low)
    - Pattern category diversity (urgency, scarcity, social proof, countdown, recurring payment)
    - Machine learning dark-pattern text classification probabilities

    Scoring Methodology:
    1. UI Risk Evidence (R, max 100):
       - Low severity detection: 15 points
       - Medium severity detection: 25 points
       - High severity detection: 40 points
       - Category diversity bonus: +10 pts for >= 2 distinct categories, +15 pts for >= 3 categories.
       - Capped at 100.
       - ML evidence: 60% max dark pattern prob + 40% avg dark pattern prob.
       - Blended risk R: round(0.60 * E_rules + 0.40 * E_ml) if ML available, else round(E_rules).
    2. Reversal to UI Safety Score:
       UI Safety Score = 100 - R (bounded 0 - 100)
       Higher = safer.
    3. UI Safety Classification:
       0 - 30:   LOW UI SAFETY
       31 - 75:  MEDIUM UI SAFETY
       76 - 100: HIGH UI SAFETY
    4. Exact Contribution Accounting:
       - Interface Design Safety: up to 60 pts (or 100 pts if ML unavailable)
       - Language Analysis Safety: up to 40 pts
       sum(ui_safety_contributions) == ui_safety_score

    Returns:
        (score, level, breakdown, signals)
    """
    detections = detections or []
    ml_results = ml_results or []
    signals: List[Dict[str, Any]] = []

    if not detections and not ml_results:
        zero_contrib = [
            {
                "signal": "interface_design_safety",
                "label": "Interface Design Safety",
                "evidence": "Clean webpage layout without manipulative patterns detected",
                "contribution_points": 60
            },
            {
                "signal": "language_analysis_safety",
                "label": "Language Analysis Safety",
                "evidence": "No deceptive or dark-pattern language detected",
                "contribution_points": 40
            }
        ]
        breakdown = {
            "detection_count": 0,
            "severity_points": 0,
            "diversity_bonus": 0,
            "rule_evidence_score": 0,
            "ml_evidence_score": None,
            "ml_available": False,
            "risk_score": 0,
            "ui_safety_score": 100,
            "formula_applied": "clean_baseline",
            "contributions": zero_contrib,
            "contribution_total": 100
        }
        signals = [
            {
                "name": "interface_design_safety",
                "label": "Interface Design Safety",
                "value": 0,
                "evidence": "Clean webpage layout without manipulative patterns detected",
                "contribution_points": 60
            },
            {
                "name": "language_analysis_safety",
                "label": "Language Analysis Safety",
                "value": 0.0,
                "evidence": "No deceptive or dark-pattern language detected",
                "contribution_points": 40
            }
        ]
        return 100, "HIGH", breakdown, signals

    # 1. Rule & Severity Analysis
    severity_weights = {
        "low": 15,
        "medium": 25,
        "high": 40
    }

    total_severity_pts = 0
    categories_seen = set()
    severity_counts = {"low": 0, "medium": 0, "high": 0}

    # Extract ML probabilities attached directly to detection objects
    detection_ml_probs: List[float] = []

    for d in detections:
        cat = str(d.get("category", "")).upper()
        if cat:
            categories_seen.add(cat)

        sev = str(d.get("severity", "low")).lower()
        if sev not in severity_weights:
            sev = "low"
        severity_counts[sev] += 1
        total_severity_pts += severity_weights[sev]

        # Check for inline ML probability on detection
        dark_prob = d.get("mlDarkPatternProb") or d.get("dark_pattern_probability")
        if dark_prob is not None:
            try:
                detection_ml_probs.append(float(dark_prob))
            except (ValueError, TypeError):
                pass
        elif d.get("mlPrediction") == "DARK_PATTERN" and d.get("mlConfidence") is not None:
            try:
                detection_ml_probs.append(float(d.get("mlConfidence")))
            except (ValueError, TypeError):
                pass

    # Category diversity bonus
    num_distinct_categories = len(categories_seen)
    diversity_bonus = 0
    if num_distinct_categories >= 3:
        diversity_bonus = 15
    elif num_distinct_categories >= 2:
        diversity_bonus = 10

    raw_rule_score = total_severity_pts + diversity_bonus
    e_rules = min(100, raw_rule_score)

    # 2. ML Evidence Analysis
    for ml in ml_results:
        dp = ml.get("dark_pattern_probability") or ml.get("darkPatternProb")
        if dp is not None:
            try:
                detection_ml_probs.append(float(dp))
            except (ValueError, TypeError):
                pass
        elif ml.get("prediction") == "DARK_PATTERN" and ml.get("confidence") is not None:
            try:
                detection_ml_probs.append(float(ml.get("confidence")))
            except (ValueError, TypeError):
                pass

    e_ml: Optional[float] = None
    max_prob: float = 0.0
    avg_prob: float = 0.0
    if detection_ml_probs:
        max_prob = max(detection_ml_probs)
        avg_prob = sum(detection_ml_probs) / len(detection_ml_probs)
        e_ml = min(100.0, (0.60 * max_prob + 0.40 * avg_prob) * 100.0)

    # 3. Final Risk Calculation & Reversal to UI Safety Score
    ui_safety_contributions: List[Dict[str, Any]] = []

    if e_ml is not None:
        raw_risk = int(round(0.60 * e_rules + 0.40 * e_ml))
        formula_used = "100 - (0.60 * rule_risk + 0.40 * ml_risk)"
        raw_risk = max(0, min(100, raw_risk))
        ui_safety_score = 100 - raw_risk

        # Exact contribution accounting (all non-negative, summing to ui_safety_score)
        rule_penalty = int(round(0.60 * e_rules))
        ml_penalty = raw_risk - rule_penalty

        rule_safety = max(0, 60 - rule_penalty)
        ml_safety = max(0, 40 - ml_penalty)

        # Guarantee exact mathematical equality
        if rule_safety + ml_safety != ui_safety_score:
            ml_safety = max(0, ui_safety_score - rule_safety)

        rule_ev = (
            "Clean layout; 0 deceptive patterns detected"
            if len(detections) == 0
            else f"{len(detections)} pattern(s) detected across {num_distinct_categories} category/ies ({rule_penalty} pts safety impact)"
        )
        ml_ev = (
            "No dark-pattern language detected"
            if max_prob == 0
            else f"Peak dark-pattern probability {max_prob:.1%} ({ml_penalty} pts safety impact)"
        )

        ui_safety_contributions.append({
            "signal": "interface_design_safety",
            "label": "Interface Design Safety",
            "evidence": rule_ev,
            "contribution_points": rule_safety
        })
        ui_safety_contributions.append({
            "signal": "language_analysis_safety",
            "label": "Language Analysis Safety",
            "evidence": ml_ev,
            "contribution_points": ml_safety
        })

        signals.append({
            "name": "interface_design_safety",
            "label": "Interface Design Safety",
            "value": len(detections),
            "evidence": rule_ev,
            "details": f"Detected {len(detections)} pattern(s) across {num_distinct_categories} category/ies. Severity breakdown: {severity_counts}",
            "contribution_points": rule_safety
        })
        signals.append({
            "name": "language_analysis_safety",
            "label": "Language Analysis Safety",
            "value": round(max_prob, 4),
            "evidence": ml_ev,
            "details": f"Max dark-pattern probability: {max_prob:.1%}, Average: {avg_prob:.1%} across {len(detection_ml_probs)} evaluated sample(s)",
            "contribution_points": ml_safety
        })
    else:
        # Graceful fallback when ML inference is unavailable
        raw_risk = int(round(e_rules))
        formula_used = "100 - rule_risk (ML unavailable)"
        raw_risk = max(0, min(100, raw_risk))
        ui_safety_score = 100 - raw_risk
        rule_safety = ui_safety_score

        rule_ev = (
            "Clean layout; 0 deceptive patterns detected"
            if len(detections) == 0
            else f"{len(detections)} pattern(s) detected across {num_distinct_categories} category/ies ({raw_risk} pts safety impact)"
        )

        ui_safety_contributions.append({
            "signal": "interface_design_safety",
            "label": "Interface Design Safety",
            "evidence": rule_ev,
            "contribution_points": rule_safety
        })
        ui_safety_contributions.append({
            "signal": "language_analysis_safety",
            "label": "Language Analysis Safety",
            "evidence": "Automated text classification offline; evaluated from interface structure",
            "contribution_points": 0
        })

        signals.append({
            "name": "interface_design_safety",
            "label": "Interface Design Safety",
            "value": len(detections),
            "evidence": rule_ev,
            "details": f"Detected {len(detections)} pattern(s) across {num_distinct_categories} category/ies. Severity breakdown: {severity_counts}",
            "contribution_points": rule_safety
        })

    safety_total = sum(c["contribution_points"] for c in ui_safety_contributions)
    level = get_score_level(ui_safety_score, is_trust=False)

    breakdown = {
        "detection_count": len(detections),
        "distinct_categories": list(categories_seen),
        "severity_counts": severity_counts,
        "severity_points": total_severity_pts,
        "diversity_bonus": diversity_bonus,
        "rule_risk_score": e_rules,
        "ml_risk_score": round(e_ml, 1) if e_ml is not None else None,
        "ml_available": e_ml is not None,
        "formula_applied": formula_used,
        "risk_score": raw_risk,
        "ui_safety_score": ui_safety_score,
        "contributions": ui_safety_contributions,
        "contribution_total": safety_total
    }

    return ui_safety_score, level, breakdown, signals


# Alias for backward compatibility
calculate_deceptive_ui_score = calculate_ui_safety_score


def calculate_store_trust_score(
    domain_intelligence: Optional[Dict[str, Any]] = None
) -> Tuple[Optional[int], str, Dict[str, Any], List[Dict[str, Any]]]:
    """
    Calculates the Store Trust Score (0 - 100) using exactly FOUR factors
    based exclusively on observed technical infrastructure signals:
    - Domain Age & Longevity (Max 40 points)
    - SSL/TLS Health & Encryption Hygiene (Max 20 points)
    - Structural Domain Characteristics (Max 20 points)
    - WHOIS & Registration Quality (Max 20 points)

    TOTAL MAXIMUM SCORE = 40 + 20 + 20 + 20 = 100 points.

    CORE PRINCIPLES:
    1. ZERO BASELINE: Trust starts at 0. Earned solely from verified empirical evidence.
    2. DIRECT ADDITION: No normalization.
    3. SSL != MERCHANT LEGITIMACY: Valid TLS encrypts transport; it does not prove the store
       is safe or authentic.
    4. NEW DOMAIN != FRAUD: A young domain has limited history (lower confidence), but
       is not automatically fraudulent.
    5. MISSING DATA != SUSPICIOUS DATA: Unverified/unavailable telemetry is marked as
       INSUFFICIENT DATA and is NOT penalized as negative evidence.
    6. EXACT CONTRIBUTION ACCOUNTING: sum(store_trust_contributions) == store_trust_score.

    Returns:
        (score, level, breakdown, signals)
    """
    signals: List[Dict[str, Any]] = []

    # If domain intelligence is completely missing or empty
    if not domain_intelligence or not isinstance(domain_intelligence, dict):
        breakdown = {
            "status": "insufficient_data",
            "reason": "Domain intelligence was not provided or could not be gathered.",
            "components": {},
            "contributions": [],
            "contribution_total": None
        }
        return None, "INSUFFICIENT_DATA", breakdown, signals

    whois_data = domain_intelligence.get("whois") or {}
    ssl_data = domain_intelligence.get("ssl") or {}
    char_data = domain_intelligence.get("domain_characteristics") or {}

    # Check if all primary data providers failed / unavailable
    whois_available = bool(whois_data.get("available") or whois_data.get("registrar") or whois_data.get("domain_age_days") is not None)
    ssl_available = bool(ssl_data.get("available") or ("valid" in ssl_data))
    char_available = bool(char_data)

    if not whois_available and not ssl_available and not char_available:
        breakdown = {
            "status": "insufficient_data",
            "reason": "WHOIS, SSL, and domain characteristics are all unavailable.",
            "components": {},
            "contributions": [],
            "contribution_total": None
        }
        return None, "INSUFFICIENT_DATA", breakdown, signals

    # -------------------------------------------------------------------------
    # 1. DOMAIN AGE — 40 POINTS MAX
    # -------------------------------------------------------------------------
    domain_age_days = (
        whois_data.get("domain_age_days")
        if whois_data.get("domain_age_days") is not None
        else char_data.get("domain_age_days")
    )

    pts_age = 0
    age_status = "unavailable"
    age_days = None

    if domain_age_days is not None:
        try:
            age_days = int(domain_age_days)
            if age_days > 1825:         # > 5 years
                pts_age = 40
                age_status = "highly_established_5yr+"
            elif age_days >= 730:       # 2 - 5 years (730 - 1825 days)
                pts_age = 35
                age_status = "established_2_to_5yr"
            elif age_days >= 365:       # 1 - 2 years (365 - 729 days)
                pts_age = 30
                age_status = "seasoned_1_to_2yr"
            elif age_days >= 181:       # 181 - 364 days
                pts_age = 22
                age_status = "developing_181_to_365d"
            elif age_days >= 91:        # 91 - 180 days
                pts_age = 15
                age_status = "developing_91_to_180d"
            elif age_days >= 30:        # 30 - 90 days
                pts_age = 8
                age_status = "young_domain_30_to_90d"
            else:                       # < 30 days
                pts_age = 0
                age_status = "newly_created_under_30d"

            age_years = round(age_days / 365.25, 1)
            age_evidence = f"Domain age is approximately {age_days} days ({age_years} years). Confidence signal reflecting historical web presence."
        except (ValueError, TypeError):
            age_status = "unverified"
            age_evidence = "Domain age unverified from WHOIS (neutral, missing data is not penalized as fraud)."
    else:
        age_status = "unverified"
        age_evidence = "Domain age unverified from WHOIS (neutral, missing data is not penalized as fraud)."

    # -------------------------------------------------------------------------
    # 2. SSL/TLS HEALTH — 20 POINTS MAX
    # -------------------------------------------------------------------------
    pts_ssl = 0
    ssl_status = "unavailable"
    ssl_evidence = ""

    if ssl_available:
        is_valid = ssl_data.get("valid")
        hostname_verified = ssl_data.get("hostname_verified")
        tls_ver = ssl_data.get("tls_version", "TLS")

        if is_valid is True and hostname_verified is not False:
            pts_ssl = 20
            ssl_status = "valid_and_verified"
            ssl_evidence = f"Valid certificate with verified hostname ({tls_ver}). Secures transmission; does not guarantee merchant legitimacy."
        elif is_valid is True and hostname_verified is False:
            pts_ssl = 10
            ssl_status = "valid_incomplete_verification"
            ssl_evidence = f"Valid certificate ({tls_ver}), but hostname verification could not be fully confirmed."
        elif is_valid is False:
            pts_ssl = 0
            ssl_status = "invalid_or_untrusted"
            err = ssl_data.get("error") or "Untrusted certificate"
            ssl_evidence = f"SSL certificate invalid or failed verification: {err}."
        else:
            pts_ssl = 0
            ssl_status = "unverified"
            ssl_evidence = "SSL/TLS certificate status unverified (neutral, missing data is not penalized as fraud)."
    else:
        err = ssl_data.get("error")
        if err and any(term in str(err).lower() for term in ["refused", "timeout", "resolution", "handshake"]):
            pts_ssl = 0
            ssl_status = "connection_failed"
            ssl_evidence = f"Unable to establish TLS handshake: {err}."
        else:
            pts_ssl = 0
            ssl_status = "unverified"
            ssl_evidence = "SSL/TLS data unavailable or unverified (neutral, missing data is not penalized as fraud)."

    # -------------------------------------------------------------------------
    # 3. DOMAIN STRUCTURE — 20 POINTS MAX
    # -------------------------------------------------------------------------
    pts_structure = 20
    structure_status = "clean"
    structure_evidence = "Standard alphanumeric conventions without anomalous patterns."
    structural_flags: List[str] = []

    raw_flags = char_data.get("suspicious_structural_flags") or []
    if char_data.get("punycode") or any("punycode" in str(f).lower() for f in raw_flags):
        structural_flags.append("punycode_homograph")
    if char_data.get("excessive_hyphens") or any("hyphen" in str(f).lower() for f in raw_flags):
        structural_flags.append("excessive_hyphens")
    if char_data.get("numeric_heavy") or any("numeric" in str(f).lower() for f in raw_flags):
        structural_flags.append("numeric_heavy")
    if char_data.get("long_hostname") or any("long_hostname" in str(f).lower() for f in raw_flags):
        structural_flags.append("long_hostname")
    if (char_data.get("subdomain_count") or 0) >= 3 or any("subdomain" in str(f).lower() for f in raw_flags):
        structural_flags.append("deep_subdomains")

    if "punycode_homograph" in structural_flags:
        pts_structure = 0
        structure_status = "punycode_homograph"
        structure_evidence = "Strong homograph / punycode character substitution detected."
    elif len(structural_flags) >= 2:
        pts_structure = 5
        structure_status = "multiple_suspicious_anomalies"
        structure_evidence = f"Multiple suspicious structural anomalies detected: {', '.join(structural_flags)}."
    elif len(structural_flags) == 1:
        pts_structure = 12
        structure_status = "mild_structural_anomaly"
        structure_evidence = f"Single mild structural anomaly detected: {structural_flags[0]}."
    else:
        pts_structure = 20
        structure_status = "clean"
        structure_evidence = "Standard alphanumeric conventions without anomalous patterns."

    # -------------------------------------------------------------------------
    # 4. WHOIS / REGISTRATION QUALITY — 20 POINTS MAX
    # -------------------------------------------------------------------------
    pts_whois = 0
    whois_status = "insufficient_data"
    whois_evidence = ""

    if whois_available:
        registrar = whois_data.get("registrar")
        name_servers = whois_data.get("name_servers") or []
        reg_status = whois_data.get("status")
        has_ns = len(name_servers) >= 2

        is_suspicious_status = False
        if reg_status:
            is_suspicious_status = any(
                s in str(reg_status).lower()
                for s in ["clienthold", "redemptionperiod", "pendingdelete"]
            )

        if is_suspicious_status:
            pts_whois = 5
            whois_status = "suspicious_registration_status"
            whois_evidence = f"Suspicious or restricted registry status ({reg_status})."
        elif registrar and has_ns:
            pts_whois = 20
            whois_status = "normal_consistent_registration"
            whois_evidence = f"Established registration record via {registrar} with {len(name_servers)} redundant nameservers."
        elif registrar or has_ns:
            pts_whois = 10
            whois_status = "partial_registration_data"
            whois_evidence = f"Partial registration record (registrar: {registrar or 'unknown'}, {len(name_servers)} nameservers)."
        else:
            pts_whois = 5
            whois_status = "inconsistent_registration"
            whois_evidence = "WHOIS record lacks standard registrar and nameserver redundancy."
    else:
        pts_whois = 0
        whois_status = "insufficient_data"
        whois_evidence = "WHOIS record unavailable or privacy-redacted (neutral, missing data is not penalized as fraud)."

    # -------------------------------------------------------------------------
    # COMPOSITE SCORE CALCULATION & EXACT CONTRIBUTION ACCOUNTING
    # -------------------------------------------------------------------------
    earned_points = pts_age + pts_ssl + pts_structure + pts_whois
    final_score = max(0, min(100, earned_points))
    level = get_score_level(final_score, is_trust=True)

    store_trust_contributions: List[Dict[str, Any]] = [
        {
            "signal": "domain_age_days",
            "label": "Domain Age",
            "evidence": age_evidence,
            "contribution_points": pts_age
        },
        {
            "signal": "ssl_tls_health",
            "label": "SSL/TLS",
            "evidence": ssl_evidence,
            "contribution_points": pts_ssl
        },
        {
            "signal": "domain_structural_characteristics",
            "label": "Domain Structure",
            "evidence": structure_evidence,
            "contribution_points": pts_structure
        },
        {
            "signal": "whois_infrastructure",
            "label": "WHOIS / Registration",
            "evidence": whois_evidence,
            "contribution_points": pts_whois
        }
    ]

    trust_total = sum(c["contribution_points"] for c in store_trust_contributions)

    signals = [
        {
            "name": "domain_age_days",
            "label": "Domain Age",
            "value": age_days,
            "status": age_status,
            "contribution_points": pts_age,
            "details": age_evidence,
            "evidence": age_evidence
        },
        {
            "name": "ssl_tls_health",
            "label": "SSL/TLS",
            "value": ssl_available,
            "status": ssl_status,
            "contribution_points": pts_ssl,
            "details": ssl_evidence,
            "evidence": ssl_evidence
        },
        {
            "name": "domain_structural_characteristics",
            "label": "Domain Structure",
            "value": structural_flags if structural_flags else "clean",
            "status": structure_status,
            "contribution_points": pts_structure,
            "details": structure_evidence,
            "evidence": structure_evidence
        },
        {
            "name": "whois_infrastructure",
            "label": "WHOIS / Registration",
            "value": whois_status,
            "status": whois_status,
            "contribution_points": pts_whois,
            "details": whois_evidence,
            "evidence": whois_evidence
        }
    ]

    breakdown = {
        "status": "available",
        "raw_score": final_score,
        "components": {
            "domain_age": {"points": pts_age, "max_points": 40, "status": age_status, "evidence": age_evidence},
            "ssl_tls": {"points": pts_ssl, "max_points": 20, "status": ssl_status, "evidence": ssl_evidence},
            "domain_structure": {"points": pts_structure, "max_points": 20, "status": structure_status, "evidence": structure_evidence},
            "whois_registration": {"points": pts_whois, "max_points": 20, "status": whois_status, "evidence": whois_evidence}
        },
        "contributions": store_trust_contributions,
        "contribution_total": trust_total
    }

    return final_score, level, breakdown, signals


def calculate_fraudguard_scores(
    detections: Optional[List[Dict[str, Any]]] = None,
    ml_results: Optional[List[Dict[str, Any]]] = None,
    domain_intelligence: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Main orchestrator calculating both independent scores:
    1. UI Safety Score (0 - 100, higher is safer)
    2. Store Trust Score (0 - 100, higher is safer)
    Returns clearly separated contributions for both scores where
    sum of contributions == displayed score.
    """
    ui_safety_score, ui_safety_level, ui_breakdown, ui_signals = calculate_ui_safety_score(
        detections=detections,
        ml_results=ml_results
    )

    trust_score, trust_level, trust_breakdown, trust_signals = calculate_store_trust_score(
        domain_intelligence=domain_intelligence
    )

    ui_contributions = ui_breakdown.get("contributions", [])
    ui_total = ui_breakdown.get("contribution_total", ui_safety_score)

    trust_contributions = trust_breakdown.get("contributions", [])
    trust_total = trust_breakdown.get("contribution_total", trust_score)

    combined_signals = ui_signals + trust_signals

    return {
        "ui_safety_score": ui_safety_score,
        "ui_safety_level": ui_safety_level,
        "ui_safety_contributions": ui_contributions,
        "ui_safety_contribution_total": ui_total,
        "store_trust_score": trust_score,
        "store_trust_level": trust_level,
        "store_trust_contributions": trust_contributions,
        "store_trust_contribution_total": trust_total,
        "ui_safety_breakdown": ui_breakdown,
        "store_trust_breakdown": trust_breakdown,
        "signals": combined_signals
    }
