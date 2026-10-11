"""
FraudGuard: Machine Learning Text Classifier Module
Provides lightweight, local inference for dark-pattern text classification.
"""

from pathlib import Path
from typing import Dict, Any, Optional
import joblib

ML_DIR = Path(__file__).resolve().parent / "ml"
MODEL_PATH = ML_DIR / "model.pkl"
VECTORIZER_PATH = ML_DIR / "vectorizer.pkl"

_MODEL = None
_VECTORIZER = None


def load_ml_assets():
    """
    Loads serialized model and vectorizer artifacts into memory.
    """
    global _MODEL, _VECTORIZER
    if _MODEL is None or _VECTORIZER is None:
        if not MODEL_PATH.exists() or not VECTORIZER_PATH.exists():
            raise FileNotFoundError(
                f"ML model artifacts not found at {MODEL_PATH} or {VECTORIZER_PATH}. "
                f"Ensure train_model.py has been executed."
            )
        _MODEL = joblib.load(MODEL_PATH)
        _VECTORIZER = joblib.load(VECTORIZER_PATH)
    return _MODEL, _VECTORIZER


def classify_text(text: str) -> Dict[str, Any]:
    """
    Classifies input text into DARK_PATTERN or NOT_DARK_PATTERN
    with a confidence score.
    """
    cleaned = (text or "").strip()
    if not cleaned:
        raise ValueError("Input text cannot be empty or whitespace only.")

    model, vectorizer = load_ml_assets()

    vec = vectorizer.transform([cleaned])
    pred_idx = int(model.predict(vec)[0])
    probas = model.predict_proba(vec)[0]
    confidence = float(probas[pred_idx])

    prediction_label = "DARK_PATTERN" if pred_idx == 1 else "NOT_DARK_PATTERN"

    return {
        "text": cleaned,
        "prediction": prediction_label,
        "confidence": round(confidence, 4),
        "dark_pattern_probability": round(float(probas[1]), 4)
    }
