"""Inference adapters for Cyber Guard's trained tabular/text classifiers."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / "trained_models"


def analyze_phishing_email_ml(text: str) -> dict[str, Any] | None:
    path = MODELS / "phishing_email_tfidf_logreg.joblib"
    if not path.exists():
        return None
    try:
        model = joblib.load(path)
        value = str(text or "")
        probability = float(model.predict_proba([value])[0][1])
        score = round(probability * 100.0, 2)
        prediction = "PHISHING" if probability >= 0.5 else "LEGITIMATE"
        return {
            "risk_score": score,
            "severity": "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 40 else "LOW" if score >= 20 else "SAFE",
            "prediction": prediction,
            "confidence": round(max(probability, 1.0 - probability) * 100.0, 2),
            "indicators": [
                f"Trained TF-IDF + Logistic Regression phishing probability: {score:.2f}%.",
                "Model trained on 10,000 balanced phishing/legitimate emails.",
            ],
            "features": {"model": "phishing_email_tfidf_logreg.joblib", "phishing_probability": round(probability, 4)},
            "recommendation": "Do not click links or share sensitive information." if score >= 60 else "Verify unexpected email requests before taking action.",
        }
    except Exception:
        return None


def _url_features(url: str) -> pd.DataFrame:
    value = str(url)
    low = value.lower()
    host = re.sub(r"^https?://", "", low).split("/")[0]
    return pd.DataFrame([[
        len(value), len(host), value.count("."), value.count("-"), value.count("@"),
        value.count("?"), value.count("="), value.count("&"), value.count("/"),
        sum(ch.isdigit() for ch in value), int("https" in low), int("@" in value),
        int(bool(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", host))),
        int(any(k in low for k in ["login", "verify", "secure", "account", "update", "bank"])),
    ]])


def analyze_phishing_url_ml(url: str) -> dict[str, Any] | None:
    path = MODELS / "phishing_url_lightgbm.txt"
    if not path.exists():
        return None
    try:
        import lightgbm as lgb
        model = lgb.Booster(model_file=str(path))
        probability = float(model.predict(_url_features(url))[0])
        score = round(probability * 100.0, 2)
        return {
            "risk_score": score,
            "severity": "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 40 else "LOW" if score >= 20 else "SAFE",
            "prediction": "PHISHING" if probability >= 0.5 else "LEGITIMATE",
            "confidence": round(max(probability, 1.0 - probability) * 100.0, 2),
            "indicators": [
                f"Trained LightGBM phishing probability: {score:.2f}%.",
                "Model trained on 50,000 balanced phishing/legitimate URLs.",
            ],
            "features": {"model": "phishing_url_lightgbm.txt", "phishing_probability": round(probability, 4)},
            "recommendation": "Avoid opening the URL until it is verified." if score >= 60 else "No strong phishing signal was found by the trained URL model.",
        }
    except Exception:
        return None
