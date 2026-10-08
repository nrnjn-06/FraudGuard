"""
FraudGuard: Intelligence & Scoring Backend
FastAPI Backend Service

Exposes endpoints for domain normalization, WHOIS registration lookup,
SSL/TLS certificate verification, ML dark-pattern text classification,
UI Safety & Store Trust scoring, and Overall Risk assessment.
"""

import time
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from domain_analyzer import normalize_domain, extract_domain_parts, analyze_domain_characteristics
from whois_analyzer import analyze_whois
from ssl_analyzer import analyze_ssl
from text_classifier import classify_text, load_ml_assets
from scoring import calculate_fraudguard_scores, calculate_overall_risk

app = FastAPI(
    title="FraudGuard Intelligence & Scoring Backend",
    description="Domain Intelligence, ML Text Classifier, Scoring Engine & Risk Assessment API",
    version="2.0.0"
)

# CORS Middleware configured for local extension communication
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(chrome-extension://.*|http://localhost(:\d+)?|http://127\.0\.0\.1(:\d+)?)$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Lightweight in-memory cache: domain -> {"timestamp": float, "data": dict}
# 10 minute cache TTL prevents repeated network hammering
CACHE_TTL_SECONDS = 600
ANALYSIS_CACHE: Dict[str, Dict[str, Any]] = {}


class DomainRequest(BaseModel):
    domain: str


class TextAnalysisRequest(BaseModel):
    text: str


class TextAnalysisResponse(BaseModel):
    text: str
    prediction: str
    confidence: float
    dark_pattern_probability: Optional[float] = None


class ScoreCalculationRequest(BaseModel):
    detections: Optional[List[Dict[str, Any]]] = None
    ml_results: Optional[List[Dict[str, Any]]] = None
    domain_intelligence: Optional[Dict[str, Any]] = None


class ScoreCalculationResponse(BaseModel):
    ui_safety_score: int
    ui_safety_level: str
    ui_safety_contributions: Optional[List[Dict[str, Any]]] = None
    ui_safety_contribution_total: Optional[int] = None
    store_trust_score: Optional[int] = None
    store_trust_level: str
    store_trust_contributions: Optional[List[Dict[str, Any]]] = None
    store_trust_contribution_total: Optional[int] = None
    ui_safety_breakdown: Dict[str, Any]
    store_trust_breakdown: Dict[str, Any]
    signals: List[Dict[str, Any]]
    risk_assessment: Optional[Dict[str, Any]] = None


class RiskCalculationRequest(BaseModel):
    store_trust_score: Optional[int] = None
    store_trust_level: Optional[str] = None
    ui_safety_score: Optional[int] = None
    ui_safety_level: Optional[str] = None
    deceptive_ui_score: Optional[int] = None  # Backward-compatibility fallback
    detections: Optional[List[Dict[str, Any]]] = None
    ml_results: Optional[List[Dict[str, Any]]] = None
    domain_intelligence: Optional[Dict[str, Any]] = None
    signals: Optional[List[Dict[str, Any]]] = None


class RiskCalculationResponse(BaseModel):
    overall_risk: str
    risk_level: str
    risk_reasons: List[str]
    risk_summary: str
    risk_guidance: str
    significant_indicator_count: Optional[int] = None
    domain_safety_summary: Optional[str] = None
    certificate_summary: Optional[str] = None
    decision_matrix_case: str
    critical_signals: List[str]
    store_trust_score: Optional[int] = None
    store_trust_level: str
    ui_safety_score: int
    ui_safety_level: str


@app.on_event("startup")
def startup_event():
    """Pre-load ML model artifacts on backend startup."""
    try:
        load_ml_assets()
        print("[FraudGuard] Launched the app successfully.")
    except Exception as exc:
        print(f"[FraudGuard] Warning: Failed to load ML model on startup: {exc}")


@app.get("/health")
def health_check():
    """Health check endpoint to verify backend status across all functional services."""
    ml_status = "unavailable"
    try:
        load_ml_assets()
        ml_status = "ready"
    except Exception:
        pass

    return {
        "status": "healthy",
        "service": "FraudGuard Intelligence & Scoring Backend",
        "domain_intelligence": "ready",
        "ml_text_classifier": ml_status,
        "scoring_engine": "ready",
        "risk_engine": "ready",
        "timestamp": time.time()
    }


def perform_domain_analysis(raw_domain: str) -> Dict[str, Any]:
    """
    Core analysis pipeline:
    1. Normalizes domain
    2. Checks in-memory cache
    3. Runs WHOIS analysis
    4. Runs SSL/TLS inspection
    5. Computes raw domain characteristics
    """
    try:
        normalized_host = normalize_domain(raw_domain)
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))

    current_time = time.time()

    # Check cache
    if normalized_host in ANALYSIS_CACHE:
        entry = ANALYSIS_CACHE[normalized_host]
        if current_time - entry["timestamp"] < CACHE_TTL_SECONDS:
            return entry["data"]

    registered_domain, subdomain, subdomain_count = extract_domain_parts(normalized_host)

    # 1. WHOIS analysis
    whois_data = analyze_whois(registered_domain)
    domain_age_days = whois_data.get("domain_age_days")

    # 2. SSL/TLS analysis
    ssl_data = analyze_ssl(normalized_host)

    # 3. Domain structural characteristics
    characteristics_data = analyze_domain_characteristics(normalized_host, domain_age_days=domain_age_days)

    # Build final structured response
    result_data = {
        "domain": normalized_host,
        "registered_domain": registered_domain,
        "whois": whois_data,
        "ssl": ssl_data,
        "domain_characteristics": characteristics_data
    }

    # Store in cache
    ANALYSIS_CACHE[normalized_host] = {
        "timestamp": current_time,
        "data": result_data
    }

    return result_data


@app.get("/analyze-domain")
def analyze_domain_get(domain: str = Query(..., description="Target domain or URL to analyze")):
    """
    GET endpoint for domain and SSL intelligence.
    Example: /analyze-domain?domain=example.com
    """
    return perform_domain_analysis(domain)


@app.post("/analyze-domain")
def analyze_domain_post(request: DomainRequest):
    """
    POST endpoint for domain and SSL intelligence.
    Example payload: {"domain": "example.com"}
    """
    return perform_domain_analysis(request.domain)


@app.post("/analyze-text", response_model=TextAnalysisResponse)
def analyze_text_post(request: TextAnalysisRequest):
    """
    POST endpoint for ML dark-pattern text classification.
    Classifies text into DARK_PATTERN or NOT_DARK_PATTERN with confidence.
    Example payload: {"text": "Hurry! Only 2 items left in stock!"}
    """
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty or whitespace only")
    try:
        return classify_text(request.text)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Text classification error: {str(exc)}")


@app.get("/analyze-text", response_model=TextAnalysisResponse)
def analyze_text_get(text: str = Query(..., description="Target webpage text to classify")):
    """
    GET endpoint for ML dark-pattern text classification.
    Example: /analyze-text?text=Hurry!+Only+2+items+left
    """
    if not text or not text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty or whitespace only")
    try:
        return classify_text(text)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Text classification error: {str(exc)}")


@app.post("/calculate-score", response_model=ScoreCalculationResponse)
def calculate_score_post(request: ScoreCalculationRequest):
    """
    POST endpoint for FraudGuard Scoring Engine.
    Dynamically calculates:
    1. UI Safety Score (0-100, higher is safer) & Level (LOW/MEDIUM/HIGH)
    2. Store Trust Score (0-100, higher is safer) & Level (LOW/MEDIUM/HIGH/INSUFFICIENT_DATA)
    Maintains complete conceptual separation: DECEPTIVE UI != FRAUD.
    Also enriches response with Overall Risk Assessment for single round-trip efficiency.
    """
    try:
        scores = calculate_fraudguard_scores(
            detections=request.detections,
            ml_results=request.ml_results,
            domain_intelligence=request.domain_intelligence
        )

        risk = calculate_overall_risk(
            store_trust_score=scores.get("store_trust_score"),
            store_trust_level=scores.get("store_trust_level"),
            ui_safety_score=scores.get("ui_safety_score"),
            ui_safety_level=scores.get("ui_safety_level"),
            detections=request.detections,
            ml_results=request.ml_results,
            domain_intelligence=request.domain_intelligence,
            signals=scores.get("signals")
        )
        scores["risk_assessment"] = risk
        return scores
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Score calculation error: {str(exc)}")


@app.post("/calculate-risk", response_model=RiskCalculationResponse)
def calculate_risk_post(request: RiskCalculationRequest):
    """
    POST endpoint for FraudGuard Overall Risk Assessment Engine.
    Combines Store Trust Score, UI Safety Score, ML dark-pattern classification,
    and domain infrastructure evidence into a transparent, explainable
    page-level risk classification (LOW / MEDIUM / HIGH).
    """
    try:
        trust_score = request.store_trust_score
        trust_level = request.store_trust_level
        ui_score = request.ui_safety_score
        ui_level = request.ui_safety_level
        signals = request.signals

        if ui_score is None and request.deceptive_ui_score is not None:
            ui_score = 100 - request.deceptive_ui_score

        if trust_score is None and ui_score is None:
            scores = calculate_fraudguard_scores(
                detections=request.detections,
                ml_results=request.ml_results,
                domain_intelligence=request.domain_intelligence
            )
            trust_score = scores.get("store_trust_score")
            trust_level = scores.get("store_trust_level")
            ui_score = scores.get("ui_safety_score")
            ui_level = scores.get("ui_safety_level")
            signals = scores.get("signals")

        return calculate_overall_risk(
            store_trust_score=trust_score,
            store_trust_level=trust_level,
            ui_safety_score=ui_score,
            ui_safety_level=ui_level,
            detections=request.detections,
            ml_results=request.ml_results,
            domain_intelligence=request.domain_intelligence,
            signals=signals
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Risk calculation error: {str(exc)}")
