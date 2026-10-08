"""
FraudGuard: ML-Based Dark-Pattern Text Detection
Model Training & Evaluation Pipeline

Trains a lightweight TF-IDF + Logistic Regression binary classifier
on the Yada e-commerce dark-pattern dataset.
Saves model artifacts and performance metrics.
"""

import json
import os
import sys
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

# Base directory paths
CURRENT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = CURRENT_DIR.parent
PROJECT_DIR = BACKEND_DIR.parent
DATASET_PATH = PROJECT_DIR / "dataset" / "dataset.csv"
if not DATASET_PATH.exists() and (PROJECT_DIR / "dataset" / "dataset (1).csv").exists():
    DATASET_PATH = PROJECT_DIR / "dataset" / "dataset (1).csv"
ML_DIR = CURRENT_DIR

MODEL_PATH = ML_DIR / "model.pkl"
VECTORIZER_PATH = ML_DIR / "vectorizer.pkl"
METRICS_PATH = ML_DIR / "metrics.json"


def load_and_validate_dataset(csv_path: Path):
    """
    Loads dataset and validates schema integrity.
    """
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset not found at {csv_path}")

    df = pd.read_csv(csv_path)
    required_cols = {"page_id", "text", "label", "Pattern Category"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"Dataset missing required columns: {missing}")

    initial_count = len(df)

    # Clean text and label
    df["text"] = df["text"].astype(str).str.strip()
    df["label"] = pd.to_numeric(df["label"], errors="coerce")

    # Drop invalid or empty rows
    df = df.dropna(subset=["text", "label"]).copy()
    df = df[df["text"].str.len() > 0].copy()
    df["label"] = df["label"].astype(int)

    # Verify binary labels (0 and 1 only)
    valid_labels = df["label"].isin([0, 1])
    df = df[valid_labels].copy()

    cleaned_count = len(df)

    stats = {
        "initial_rows": initial_count,
        "cleaned_rows": cleaned_count,
        "dropped_rows": initial_count - cleaned_count,
        "label_counts": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "category_counts": {str(k): int(v) for k, v in df["Pattern Category"].value_counts().items()},
    }

    return df, stats


def train_and_evaluate(df: pd.DataFrame, random_seed: int = 42):
    """
    Splits dataset (80/20 stratified), trains TF-IDF + Logistic Regression,
    and calculates comprehensive evaluation metrics.
    """
    X = df["text"].values
    y = df["label"].values

    # Stratified 80/20 train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=random_seed,
        stratify=y
    )

    # TF-IDF Vectorizer fitted ONLY on train set
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        stop_words="english",
        sublinear_tf=True
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Logistic Regression classifier fitted ONLY on train set
    classifier = LogisticRegression(
        C=1.0,
        max_iter=1000,
        random_state=random_seed,
        solver="lbfgs"
    )
    classifier.fit(X_train_vec, y_train)

    # Predictions & probabilities on unseen test set
    y_pred = classifier.predict(X_test_vec)
    y_proba = classifier.predict_proba(X_test_vec)[:, 1]

    # Metrics calculation
    accuracy = float(accuracy_score(y_test, y_pred))
    precision = float(precision_score(y_test, y_pred, pos_label=1))
    recall = float(recall_score(y_test, y_pred, pos_label=1))
    f1 = float(f1_score(y_test, y_pred, pos_label=1))
    roc_auc = float(roc_auc_score(y_test, y_proba))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    report_dict = classification_report(y_test, y_pred, output_dict=True)

    metrics = {
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "confusion_matrix": {
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "true_positive": tp
        },
        "classification_report": report_dict,
        "hyperparameters": {
            "model": "LogisticRegression",
            "C": 1.0,
            "max_iter": 1000,
            "solver": "lbfgs",
            "vectorizer": "TfidfVectorizer",
            "max_features": 5000,
            "ngram_range": [1, 2],
            "sublinear_tf": True,
            "stop_words": "english",
            "random_state": random_seed
        }
    }

    return classifier, vectorizer, metrics


def test_mandatory_sentences(classifier, vectorizer):
    """
    Evaluates model inference on mandatory standard test sentences.
    """
    test_cases = [
        ("Hurry! Only 2 items left in stock!", "DARK_PATTERN"),
        ("Free shipping on orders over $50", "NOT_DARK_PATTERN"),
        ("Someone just bought this item 5 minutes ago", "DARK_PATTERN"),
        ("Contact us at support@example.com", "NOT_DARK_PATTERN"),
    ]

    results = []
    print("\n--- Mandatory Test Sentences Evaluation ---")
    for text, expected in test_cases:
        vec_text = vectorizer.transform([text])
        pred_idx = int(classifier.predict(vec_text)[0])
        probas = classifier.predict_proba(vec_text)[0]
        confidence = float(probas[pred_idx])

        pred_label = "DARK_PATTERN" if pred_idx == 1 else "NOT_DARK_PATTERN"
        is_correct = pred_label == expected

        result = {
            "text": text,
            "expected": expected,
            "predicted": pred_label,
            "confidence": round(confidence, 4),
            "dark_pattern_prob": round(float(probas[1]), 4),
            "correct": is_correct
        }
        results.append(result)
        status_sym = "[PASS]" if is_correct else "[FAIL]"
        print(f"{status_sym} '{text}' -> {pred_label} (Confidence: {confidence:.2%}, Expected: {expected})")

    return results


def main():
    print(f"Loading dataset from: {DATASET_PATH}")
    df, stats = load_and_validate_dataset(DATASET_PATH)
    print(f"Dataset loaded successfully: {stats['cleaned_rows']} valid rows (0 dropped).")
    print(f"Label distribution: {stats['label_counts']}")
    print(f"Pattern categories: {stats['category_counts']}")

    print("\nTraining TF-IDF + Logistic Regression model...")
    classifier, vectorizer, metrics = train_and_evaluate(df)

    print("\n--- Test Set Evaluation Results (20% unseen test split) ---")
    print(f"Accuracy:  {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall:    {metrics['recall']:.4f}")
    print(f"F1-Score:  {metrics['f1_score']:.4f}")
    print(f"ROC-AUC:   {metrics['roc_auc']:.4f}")
    print("Confusion Matrix:")
    print(f"  TN: {metrics['confusion_matrix']['true_negative']}  | FP: {metrics['confusion_matrix']['false_positive']}")
    print(f"  FN: {metrics['confusion_matrix']['false_negative']}  | TP: {metrics['confusion_matrix']['true_positive']}")

    # Save artifacts
    ML_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(classifier, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"\nArtifacts saved to:\n  - {MODEL_PATH}\n  - {VECTORIZER_PATH}")

    # Test sample sentences
    test_results = test_mandatory_sentences(classifier, vectorizer)
    metrics["test_sentence_results"] = test_results
    metrics["dataset_stats"] = stats

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"Metrics saved to: {METRICS_PATH}")


if __name__ == "__main__":
    main()
