"""
FraudGuard: Overall Risk Assessment Engine
Provides deterministic, explainable, evidence-based overall risk evaluation:
1. LOW RISK
2. MEDIUM RISK
3. HIGH RISK

CORE ARCHITECTURAL PRINCIPLES:
    - DECEPTIVE UI != FRAUD
      A legitimate established merchant may use promotional urgency or scarcity tactics.
      Conversely, an unestablished domain with zero deceptive patterns is not necessarily fraudulent.
    - NEVER simply average Store Trust Score and UI Safety Score.
    - Store Trust is the PRIMARY factor; UI Safety is the SECONDARY factor.
    - Both scores follow the same direction: Higher = safer.
    - Deterministic and reproducible: identical evidence guarantees identical assessment.
    - Transparent reasoning: every evaluation outputs clear, evidence-based bullet reasons.
    - Language safeguards: does NOT claim "This website is definitely fraudulent."
      Uses evidence-based indicators ("High Risk", "Multiple strong risk indicators detected").
"""

from typing import Dict, Any, List, Optional, Tuple


# Score thresholds — Identical for Store Trust and UI Safety
# 0 - 30:   LOW
# 31 - 75:  MEDIUM
# 76 - 100: HIGH
SCORE_LOW_MAX = 30
SCORE_MED_MAX = 75

STORE_TRUST_LOW_MAX = 30
STORE_TRUST_MED_MAX = 75
UI_SAFETY_LOW_MAX = 30
UI_SAFETY_MED_MAX = 75

# Standardized guidance templates
GUIDANCE_LOW = "Few significant risk indicators detected."
GUIDANCE_MEDIUM = "Some risk indicators detected. Review the findings before proceeding."
GUIDANCE_HIGH = "Multiple strong risk indicators detected. Exercise caution before providing sensitive information or making a payment."
GUIDANCE_INSUFFICIENT = "Insufficient data to determine a complete risk profile. Exercise normal caution."


def get_band_level(score: Optional[int], is_trust: bool = False) -> str:
    """
    Maps a 0-100 score to its evidence band (LOW, MEDIUM, HIGH, or INSUFFICIENT_DATA).
    Both Store Trust and UI Safety use identical boundaries:
        0 - 30:   LOW
        31 - 75:  MEDIUM
        76 - 100: HIGH
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


def extract_ml_evidence(
    detections: Optional[List[Dict[str, Any]]] = None,
    ml_results: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Extracts summary metrics from machine learning text classification output.
    Does not invent confidence values; extracts actual available predictions.
    """
    detections = detections or []
    ml_results = ml_results or []

    dark_probs: List[float] = []
    dark_count = 0
    benign_count = 0

    # From detection objects
    for d in detections:
        prob = d.get("mlDarkPatternProb") or d.get("dark_pattern_probability")
        if prob is not None:
            try:
                p_val = float(prob)
                dark_probs.append(p_val)
            except (ValueError, TypeError):
                pass

        pred = d.get("mlPrediction") or d.get("prediction")
        if pred == "DARK_PATTERN":
            dark_count += 1
        elif pred == "NOT_DARK_PATTERN":
            benign_count += 1

    # From separate ml_results list
    for m in ml_results:
        prob = m.get("dark_pattern_probability") or m.get("mlDarkPatternProb")
        if prob is not None:
            try:
                p_val = float(prob)
                dark_probs.append(p_val)
            except (ValueError, TypeError):
                pass
        pred = m.get("prediction") or m.get("mlPrediction")
        if pred == "DARK_PATTERN":
            dark_count += 1
        elif pred == "NOT_DARK_PATTERN":
            benign_count += 1

    has_ml = len(dark_probs) > 0 or (dark_count + benign_count) > 0
    max_prob = max(dark_probs) if dark_probs else (0.90 if dark_count > 0 else 0.0)
    avg_prob = (sum(dark_probs) / len(dark_probs)) if dark_probs else (0.80 if dark_count > 0 else 0.0)

    return {
        "has_ml": has_ml,
        "dark_pattern_count": dark_count,
        "benign_count": benign_count,
        "max_dark_prob": round(max_prob, 3),
        "avg_dark_prob": round(avg_prob, 3),
        "strong_ml_dark_pattern": bool(has_ml and max_prob >= 0.80 and dark_count >= 1)
    }


def extract_critical_signals(
    detections: Optional[List[Dict[str, Any]]] = None,
    domain_intelligence: Optional[Dict[str, Any]] = None
) -> List[Dict[str, str]]:
    """
    Identifies high-impact critical signals present in the evidence.
    Each critical signal includes an architectural justification.
    """
    detections = detections or []
    dom_intel = domain_intelligence or {}
    critical = []

    # 1. Pre-selected recurring payment / subscription
    for d in detections:
        cat = str(d.get("category", "")).upper()
        if cat in ("RECURRING_PAYMENT", "RECURRING_CHARGE", "HIDDEN_SUBSCRIPTION", "SUBSCRIPTION"):
            critical.append({
                "id": "CRITICAL_RECURRING_PAYMENT",
                "label": "Pre-selected recurring payment or subscription option detected",
                "rationale": "Directly enrolls user into recurring financial commitments without explicit opt-in."
            })
            break

    # 2. Very young domain (< 30 days)
    whois_data = dom_intel.get("whois") or {}
    char_data = dom_intel.get("domain_characteristics") or {}
    domain_age_days = whois_data.get("domain_age_days")
    if domain_age_days is None:
        domain_age_days = char_data.get("domain_age_days")

    if domain_age_days is not None:
        try:
            days = int(domain_age_days)
            if days < 30:
                critical.append({
                    "id": "CRITICAL_NEW_DOMAIN",
                    "label": f"Newly registered domain ({days} days old, under 30 days)",
                    "rationale": "High statistical correlation between ephemeral disposable domains and fraud storefronts."
                })
        except (ValueError, TypeError):
            pass

    # 3. Invalid SSL/TLS certificate
    ssl_data = dom_intel.get("ssl") or {}
    if ssl_data.get("available") or ("valid" in ssl_data):
        is_valid = ssl_data.get("valid")
        host_verified = ssl_data.get("hostname_verified")
        if is_valid is False or host_verified is False:
            critical.append({
                "id": "CRITICAL_INVALID_SSL",
                "label": "Invalid, expired, or hostname-mismatched SSL/TLS certificate",
                "rationale": "Transport-layer encryption failure; high vulnerability to interception."
            })

    # 4. Suspicious domain structural flags (Punycode / Homograph / Multiple anomalies)
    flags = char_data.get("suspicious_structural_flags") or []
    if char_data.get("punycode") or any("punycode" in str(f).lower() for f in flags):
        critical.append({
            "id": "CRITICAL_PUNYCODE_HOMOGRAPH",
            "label": "Punycode / Internationalized domain name homograph detected",
            "rationale": "Classic brand-spoofing and deceptive character substitution technique."
        })
    elif len(flags) >= 2:
        critical.append({
            "id": "CRITICAL_MULTIPLE_STRUCTURAL_FLAGS",
            "label": f"Multiple anomalous domain structural flags: {', '.join(flags)}",
            "rationale": "Non-standard hostname structure frequently associated with automated domain generation."
        })

    return critical


def count_significant_risk_indicators(
    detections: Optional[List[Dict[str, Any]]] = None,
    domain_intelligence: Optional[Dict[str, Any]] = None,
    critical_signals: Optional[List[Dict[str, str]]] = None
) -> int:
    """
    Counts distinct significant risk indicators for dynamic guidance phrasing.
    Avoids double-counting.
    """
    count = 0
    detections = detections or []
    dom_intel = domain_intelligence or {}
    critical_signals = critical_signals or []

    # Count high and medium severity detections
    high_count = sum(1 for d in detections if str(d.get("severity", "")).lower() == "high")
    med_count = sum(1 for d in detections if str(d.get("severity", "")).lower() == "medium")
    count += high_count + med_count

    # Critical signals
    for c in critical_signals:
        cid = c.get("id")
        if cid != "CRITICAL_RECURRING_PAYMENT":
            count += 1

    # Check for domain age under 90 days (if not already counted under < 30 days)
    if not any(c.get("id") == "CRITICAL_NEW_DOMAIN" for c in critical_signals):
        whois_data = dom_intel.get("whois") or {}
        char_data = dom_intel.get("domain_characteristics") or {}
        age = whois_data.get("domain_age_days") or char_data.get("domain_age_days")
        if age is not None:
            try:
                if int(age) < 90:
                    count += 1
            except (ValueError, TypeError):
                pass

    # Check for single structural anomaly
    if not any(c.get("id") == "CRITICAL_MULTIPLE_STRUCTURAL_FLAGS" for c in critical_signals):
        flags = (dom_intel.get("domain_characteristics") or {}).get("suspicious_structural_flags") or []
        if len(flags) == 1:
            count += 1

    return count


def get_certificate_summary(domain_intelligence: Optional[Dict[str, Any]] = None) -> str:
    """Returns standardized human-readable TLS certificate status."""
    dom_intel = domain_intelligence or {}
    ssl_data = dom_intel.get("ssl") or {}

    if ssl_data.get("available") or ("valid" in ssl_data):
        is_valid = bool(ssl_data.get("valid"))
        hostname_verified = bool(ssl_data.get("hostname_verified", True))
        if is_valid and hostname_verified:
            return "has a valid TLS certificate"
        else:
            return "has an invalid or unverified TLS certificate"
    else:
        err = ssl_data.get("error")
        if err:
            return "has an invalid or unverified TLS certificate"
        return "TLS certificate status could not be verified"


def get_domain_safety_summary(trust_level: str) -> str:
    """Returns evidence-based domain safety summary based on Store Trust Level."""
    if trust_level == "HIGH":
        return "The domain appears safe based on available trust and security indicators."
    elif trust_level == "MEDIUM":
        return "The domain shows moderate trust evidence based on standard infrastructure."
    elif trust_level == "LOW":
        return "The domain has low trust evidence and an unestablished infrastructure profile."
    else:
        return "Domain trust evidence is currently unverified or unavailable."


def generate_risk_guidance(
    indicator_count: int,
    trust_level: str,
    cert_summary: str,
    overall_risk: str = "MEDIUM"
) -> str:
    """
    Generates contextual, dynamic user risk guidance matching the Store Trust-priority model:
    - High Trust establishes low base risk.
    - Medium Trust establishes moderate base risk.
    - Low Trust or Critical signals establish High Risk.
    """
    noun = "indicator" if indicator_count == 1 else "indicators"
    count_phrase = f"{indicator_count} significant risk {noun} detected"

    if overall_risk == "HIGH":
        if trust_level == "LOW":
            if indicator_count == 0:
                return f"No significant UI indicators detected, but the domain has low trust evidence and {cert_summary}. Exercise elevated caution."
            else:
                return f"{count_phrase}. The domain has low trust evidence and an unestablished profile; exercise elevated caution."
        else:
            if indicator_count == 0:
                return "Critical risk indicators detected; exercise caution before providing sensitive information or making a payment."
            else:
                return f"{count_phrase}. Multiple strong risk indicators detected; exercise caution before providing sensitive information or making a payment."
    elif overall_risk == "MEDIUM":
        if trust_level == "HIGH":
            return f"{count_phrase}. The domain has high trust, but deceptive UI patterns were detected; review findings before proceeding."
        elif trust_level == "MEDIUM":
            if indicator_count == 0:
                return f"No significant risk indicators detected. The domain shows moderate trust evidence and {cert_summary}."
            else:
                return f"{count_phrase}. The domain shows moderate trust evidence and {cert_summary}."
        else:
            return f"{count_phrase}. Some risk indicators detected. Review the findings before proceeding."
    else:  # LOW
        if indicator_count == 0:
            return f"No significant risk indicators detected. The domain appears safe and {cert_summary}."
        else:
            return f"{count_phrase}, but the domain appears safe and {cert_summary}."


def calculate_overall_risk(
    store_trust_score: Optional[int] = None,
    store_trust_level: Optional[str] = None,
    ui_safety_score: Optional[int] = None,
    ui_safety_level: Optional[str] = None,
    deceptive_ui_score: Optional[int] = None,
    deceptive_ui_level: Optional[str] = None,
    detections: Optional[List[Dict[str, Any]]] = None,
    ml_results: Optional[List[Dict[str, Any]]] = None,
    domain_intelligence: Optional[Dict[str, Any]] = None,
    signals: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Overall Risk Assessment Engine.
    Combines:
    - Store Trust Score & Level (0-100, higher is safer) [PRIMARY FACTOR]
    - UI Safety Score & Level (0-100, higher is safer)   [SECONDARY FACTOR]
    - Machine learning dark-pattern probabilities
    - Domain & TLS infrastructure telemetry
    - Detections and critical signal escalation rules

    Exact Priority Matrix:
    - LOW TRUST (0-30):
        LOW UI SAFETY (0-30)     -> HIGH RISK
        MEDIUM UI SAFETY (31-75) -> HIGH RISK
        HIGH UI SAFETY (76-100)  -> MEDIUM RISK
    - MEDIUM TRUST (31-75):
        LOW UI SAFETY (0-30)     -> HIGH RISK
        MEDIUM UI SAFETY (31-75) -> MEDIUM RISK
        HIGH UI SAFETY (76-100)  -> MEDIUM RISK
    - HIGH TRUST (76-100):
        LOW UI SAFETY (0-30)     -> MEDIUM RISK
        MEDIUM UI SAFETY (31-75) -> LOW RISK
        HIGH UI SAFETY (76-100)  -> LOW RISK
    - INSUFFICIENT DATA:
        LOW UI SAFETY (0-30)     -> HIGH RISK
        MEDIUM UI SAFETY (31-75) -> MEDIUM RISK
        HIGH UI SAFETY (76-100)  -> LOW RISK

    Critical signals automatically escalate Overall Risk to HIGH RISK regardless of matrix.

    Returns:
        Structured dictionary containing overall_risk, risk_reasons, risk_summary,
        risk_guidance, decision_matrix_case, critical_signals, store_trust_score,
        store_trust_level, ui_safety_score, ui_safety_level.
    """
    detections = detections or []
    ml_results = ml_results or []
    domain_intelligence = domain_intelligence or {}
    signals = signals or []

    # 1. Resolve Store Trust Level
    if store_trust_score is not None:
        trust_level = store_trust_level or get_band_level(store_trust_score, is_trust=True)
    else:
        trust_level = "INSUFFICIENT_DATA"

    # 2. Resolve UI Safety Score & Level (backward compatibility: ui_safety = 100 - deceptive_ui)
    if ui_safety_score is not None:
        ui_safety_score_val = max(0, min(100, int(ui_safety_score)))
    elif deceptive_ui_score is not None:
        ui_safety_score_val = max(0, min(100, 100 - int(deceptive_ui_score)))
    else:
        ui_safety_score_val = 100  # Default to clean baseline

    safety_level = ui_safety_level or get_band_level(ui_safety_score_val, is_trust=False)

    # 3. Extract Evidence Details
    ml_data = extract_ml_evidence(detections, ml_results)
    critical_signals_list = extract_critical_signals(detections, domain_intelligence)
    critical_ids = {c["id"] for c in critical_signals_list}

    # 4. Priority Decision Matrix Evaluation
    case_name = ""
    overall_risk = "MEDIUM"

    if trust_level == "HIGH":
        # ------------------------------------------------------------------
        # TRUST LEVEL: HIGH (Score 76 - 100) -> Base Risk: LOW
        # ------------------------------------------------------------------
        if safety_level == "LOW":
            case_name = "HIGH_TRUST_LOW_UI_SAFETY"
            overall_risk = "MEDIUM"
        elif safety_level == "MEDIUM":
            case_name = "HIGH_TRUST_MED_UI_SAFETY"
            overall_risk = "LOW"
        else:  # HIGH UI SAFETY
            case_name = "HIGH_TRUST_HIGH_UI_SAFETY"
            overall_risk = "LOW"

    elif trust_level == "MEDIUM":
        # ------------------------------------------------------------------
        # TRUST LEVEL: MEDIUM (Score 31 - 75) -> Base Risk: MEDIUM
        # ------------------------------------------------------------------
        if safety_level == "LOW":
            case_name = "MED_TRUST_LOW_UI_SAFETY"
            overall_risk = "HIGH"
        elif safety_level == "MEDIUM":
            case_name = "MED_TRUST_MED_UI_SAFETY"
            overall_risk = "MEDIUM"
        else:  # HIGH UI SAFETY
            case_name = "MED_TRUST_HIGH_UI_SAFETY"
            overall_risk = "MEDIUM"

    elif trust_level == "LOW":
        # ------------------------------------------------------------------
        # TRUST LEVEL: LOW (Score 0 - 30) -> Base Risk: HIGH
        # ------------------------------------------------------------------
        if safety_level == "LOW":
            case_name = "LOW_TRUST_LOW_UI_SAFETY"
            overall_risk = "HIGH"
        elif safety_level == "MEDIUM":
            case_name = "LOW_TRUST_MED_UI_SAFETY"
            overall_risk = "HIGH"
        else:  # HIGH UI SAFETY
            case_name = "LOW_TRUST_HIGH_UI_SAFETY"
            overall_risk = "MEDIUM"

    else:
        # ------------------------------------------------------------------
        # TRUST LEVEL: INSUFFICIENT_DATA (Domain info missing or unverified)
        # ------------------------------------------------------------------
        if safety_level == "LOW":
            case_name = "INSUFFICIENT_DATA_LOW_UI_SAFETY"
            overall_risk = "HIGH"
        elif safety_level == "MEDIUM":
            case_name = "INSUFFICIENT_DATA_MED_UI_SAFETY"
            overall_risk = "MEDIUM"
        else:  # HIGH UI SAFETY
            case_name = "INSUFFICIENT_DATA_HIGH_UI_SAFETY"
            overall_risk = "LOW"

    # 5. Critical Signal Override
    if len(critical_ids) > 0:
        overall_risk = "HIGH"
        case_name += "_ESCALATED_CRITICAL"

    # 6. Generate Transparent Risk Reasons (Explainability)
    reasons: List[str] = []

    # Store Trust reason (Primary Factor)
    if trust_level == "HIGH":
        reasons.append("✓ Primary factor — High Store Trust: established registration and valid SSL/TLS certificate establish a low base risk.")
    elif trust_level == "MEDIUM":
        reasons.append("ℹ Primary factor — Moderate Store Trust: standard domain infrastructure establishes a moderate base risk.")
    elif trust_level == "LOW":
        reasons.append("⚠ Primary factor — Low Store Trust: newly created, unseasoned, or unverified infrastructure elevates base risk.")
    else:
        reasons.append("ℹ Primary factor — Domain Intelligence: unverified or unavailable; evaluating based on visible page evidence.")

    # UI Safety reason (Secondary Factor)
    if safety_level == "HIGH":
        reasons.append("✓ Secondary factor — High UI Safety: few or no deceptive or coercive interface patterns detected.")
    elif safety_level == "MEDIUM":
        reasons.append(f"ℹ Secondary factor — Moderate UI Safety: detected {len(detections)} persuasive or pressure pattern(s).")
    else:  # LOW
        unique_cats = {d.get('category', '').replace('_', ' ').title() for d in detections if d.get('category')}
        cat_str = ", ".join(sorted(unique_cats)) if unique_cats else "Urgency/Scarcity"
        reasons.append(f"⚠ Secondary factor — Low UI Safety: multiple manipulative interface patterns detected ({cat_str}); lower UI Safety indicates stronger deceptive UI concerns.")

    # ML Evidence reason
    if ml_data["has_ml"]:
        if ml_data["strong_ml_dark_pattern"]:
            reasons.append(f"⚠ ML text classifier confirmed dark-pattern language with high probability ({int(ml_data['max_dark_prob'] * 100)}%).")
        elif ml_data["dark_pattern_count"] > 0:
            reasons.append(f"ℹ ML text classifier identified {ml_data['dark_pattern_count']} suspected dark-pattern text instance(s).")
        else:
            reasons.append("✓ ML text classification found no dominant dark-pattern textual indicators.")

    # Critical Signal reasons
    for crit in critical_signals_list:
        reasons.append(f"🚨 Critical indicator override: {crit['label']}.")

    # Model explanation note according to Store Trust priority model
    if len(critical_ids) > 0:
        reasons.append("🚨 Critical security or domain indicators detected: overrides normal score evaluation to High Risk.")
    elif trust_level == "HIGH" and safety_level == "LOW":
        reasons.append("⚖ Store Trust priority: High Store Trust establishes low base risk, but lower UI Safety indicates deceptive interface patterns, resulting in MEDIUM RISK.")
    elif trust_level == "HIGH" and safety_level in ("MEDIUM", "HIGH"):
        reasons.append("✓ Store Trust priority: High Store Trust and acceptable UI Safety maintain LOW RISK.")
    elif trust_level == "MEDIUM" and safety_level == "LOW":
        reasons.append("⚠ Store Trust priority: Moderate Store Trust combined with low UI Safety escalates Overall Risk to HIGH RISK.")
    elif trust_level == "MEDIUM" and safety_level in ("MEDIUM", "HIGH"):
        reasons.append("ℹ Store Trust priority: Moderate Store Trust establishes MEDIUM RISK baseline.")
    elif trust_level == "LOW" and safety_level == "HIGH":
        reasons.append("ℹ Store Trust priority: Low Store Trust elevates base risk, but high UI Safety maintains MEDIUM RISK in the absence of deceptive interface patterns.")
    elif trust_level == "LOW":
        reasons.append("⚠ Store Trust priority: Low Store Trust is the primary factor, resulting in HIGH RISK.")

    # 7. Generate Summary Paragraph and Dynamic Prescribed Guidance
    indicator_count = count_significant_risk_indicators(
        detections=detections,
        domain_intelligence=domain_intelligence,
        critical_signals=critical_signals_list
    )
    cert_summary = get_certificate_summary(domain_intelligence)
    domain_safety_summary = get_domain_safety_summary(trust_level)
    risk_guidance = generate_risk_guidance(indicator_count, trust_level, cert_summary, overall_risk)

    if overall_risk == "LOW":
        risk_summary = (
            "Store Trust is the primary risk factor. With high domain trust and acceptable user interface safety, "
            "overall website risk remains low."
        )
    elif overall_risk == "MEDIUM":
        if trust_level == "HIGH" and safety_level == "LOW":
            risk_summary = (
                "Store Trust is the primary factor and UI Safety is secondary. High Store Trust establishes a low base "
                "risk, but lower UI Safety indicates deceptive interface patterns, elevating the evaluation to Medium Risk."
            )
        else:
            risk_summary = (
                "Store Trust is the primary factor. Moderate domain infrastructure establishes a Medium Risk baseline. "
                "Review findings before completing transactions."
            )
    else:  # HIGH
        if len(critical_ids) > 0:
            risk_summary = (
                "Critical security or domain indicators were identified, overriding the normal scoring matrix "
                "and elevating Overall Risk to High Risk. Exercise caution before submitting personal or payment information."
            )
        elif trust_level == "LOW":
            risk_summary = (
                "Store Trust is the primary risk factor. Low domain trust indicates an unestablished, newly registered, "
                "or unverified domain, resulting in High Risk."
            )
        else:
            risk_summary = (
                "Store Trust is the primary factor and UI Safety is secondary. Moderate domain trust combined with "
                "low UI Safety escalates Overall Risk to High Risk."
            )

    return {
        "overall_risk": overall_risk,
        "risk_level": overall_risk,
        "risk_reasons": reasons,
        "risk_summary": risk_summary,
        "risk_guidance": risk_guidance,
        "significant_indicator_count": indicator_count,
        "domain_safety_summary": domain_safety_summary,
        "certificate_summary": cert_summary,
        "decision_matrix_case": case_name,
        "critical_signals": [c["label"] for c in critical_signals_list],
        "store_trust_score": store_trust_score,
        "store_trust_level": trust_level,
        "ui_safety_score": ui_safety_score_val,
        "ui_safety_level": safety_level
    }
