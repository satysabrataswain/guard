"""
Central Risk Scoring, Severity Classification,
Explainability and Recommended Response Engine.

Guard Security Platform
"""

from __future__ import annotations

from typing import Any


# ============================================================================
# RISK LEVEL CONFIGURATION
# ============================================================================

RISK_LEVELS = {
    "SAFE": (0, 19),
    "LOW": (20, 39),
    "MEDIUM": (40, 59),
    "HIGH": (60, 79),
    "CRITICAL": (80, 100),
}


# ============================================================================
# MODEL WEIGHTS
# ============================================================================

MODEL_WEIGHTS = {
    "URL_PHISHING_ENGINE": 1.30,
    "EMAIL_NLP_ENGINE": 1.20,
    "MESSAGE_NLP_ENGINE": 1.20,
    "NLP_ENGINE": 1.20,
    "LOGIN_ANOMALY_ENGINE": 1.30,
    "BEHAVIOUR_ANOMALY_ENGINE": 1.10,
    "IMAGE_ENGINE": 1.25,
    "VIDEO_ENGINE": 1.30,
    "DEEPFAKE_ENGINE": 1.40,
    "IDENTITY_ENGINE": 1.30,
    "NETWORK_ENGINE": 1.30,
    "MALWARE_ENGINE": 1.50,
    "EMBER_MALWARE_ENGINE": 1.60,
    "PHISHING_URL_ML_ENGINE": 1.30,
    "PHISHING_EMAIL_ML_ENGINE": 1.25,
    "VOICE_ENGINE": 1.40,
}


# ============================================================================
# SEVERITY WEIGHTS / RESPONSE THRESHOLDS
# ============================================================================

AUTO_ESCALATE_SEVERITY = {
    "HIGH",
    "CRITICAL",
}


# ============================================================================
# NORMALIZATION HELPERS
# ============================================================================


def _clamp(
    value: Any,
    minimum: float = 0.0,
    maximum: float = 100.0,
) -> float:
    """
    Safely normalize a numeric value into a fixed range.
    """

    try:
        numeric_value = float(value)

    except (
        TypeError,
        ValueError,
    ):
        numeric_value = minimum

    return round(
        max(
            minimum,
            min(
                maximum,
                numeric_value,
            ),
        ),
        2,
    )


def _safe_score(
    value: Any,
) -> float:
    """
    Normalize a model score to 0-100.
    """

    return _clamp(value)


def _safe_weight(
    model_name: str,
) -> float:
    """
    Return configured model weight.

    Unknown engines intentionally receive a neutral weight of 1.0.
    """

    return float(
        MODEL_WEIGHTS.get(
            model_name,
            1.0,
        )
    )


# ============================================================================
# SEVERITY
# ============================================================================


def get_severity(
    score: float,
) -> str:
    """
    Convert a 0-100 risk score into Guard severity.
    """

    score = _safe_score(score)

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    if score >= 20:
        return "LOW"

    return "SAFE"


# ============================================================================
# SCORE NORMALIZATION
# ============================================================================


def normalize_scores(
    scores: dict[str, Any] | None,
) -> dict[str, float]:
    """
    Clean and normalize incoming engine scores.

    Invalid scores are ignored rather than breaking the complete
    threat-analysis request.
    """

    if not isinstance(
        scores,
        dict,
    ):
        return {}

    normalized = {}

    for model_name, raw_score in scores.items():

        if not model_name:
            continue

        try:
            score = float(raw_score)

        except (
            TypeError,
            ValueError,
        ):
            continue

        normalized[
            str(model_name)
        ] = _safe_score(
            score
        )

    return normalized


# ============================================================================
# WEIGHTED RISK SCORE
# ============================================================================


def calculate_weighted_average(
    scores: dict[str, Any],
) -> float:
    """
    Calculate weighted average of all valid model scores.
    """

    normalized = normalize_scores(
        scores
    )

    if not normalized:
        return 0.0

    weighted_total = 0.0
    total_weight = 0.0

    for model_name, score in normalized.items():

        weight = _safe_weight(
            model_name
        )

        weighted_total += (
            score * weight
        )

        total_weight += weight

    if total_weight <= 0:
        return 0.0

    return _clamp(
        weighted_total / total_weight
    )


def calculate_risk_score(
    scores: dict[str, Any],
) -> float:
    """
    Calculate final Guard risk score.

    Strategy:

    1. Normalize every engine score.
    2. Calculate weighted average.
    3. Identify strongest security signal.
    4. Blend weighted average + strongest signal.
    5. Apply high-risk protection so a dangerous signal
       cannot be completely hidden by low scores from
       other engines.
    """

    normalized = normalize_scores(
        scores
    )

    if not normalized:
        return 0.0

    weighted_average = calculate_weighted_average(
        normalized
    )

    strongest_signal = max(
        normalized.values()
    )

    # The strongest model signal gets meaningful influence.
    blended_score = (
        weighted_average * 0.60
        + strongest_signal * 0.40
    )

    # If one engine is extremely confident, do not allow
    # other low scores to reduce the final result too much.
    if strongest_signal >= 90:
        blended_score = max(
            blended_score,
            strongest_signal * 0.85,
        )

    elif strongest_signal >= 80:
        blended_score = max(
            blended_score,
            strongest_signal * 0.75,
        )

    elif strongest_signal >= 70:
        blended_score = max(
            blended_score,
            strongest_signal * 0.70,
        )

    return _clamp(
        blended_score
    )


# ============================================================================
# MODEL CONTRIBUTION
# ============================================================================


def get_model_contributions(
    scores: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Return explainable contribution information for every engine.
    """

    normalized = normalize_scores(
        scores
    )

    if not normalized:
        return []

    total_weight = sum(
        _safe_weight(
            model_name
        )
        for model_name in normalized
    )

    if total_weight <= 0:
        total_weight = 1.0

    contributions = []

    for model_name, score in normalized.items():

        weight = _safe_weight(
            model_name
        )

        contribution = (
            score
            * weight
            / total_weight
        )

        if score >= 80:
            signal_level = "CRITICAL"

        elif score >= 60:
            signal_level = "HIGH"

        elif score >= 40:
            signal_level = "MEDIUM"

        elif score >= 20:
            signal_level = "LOW"

        else:
            signal_level = "SAFE"

        contributions.append(
            {
                "model": model_name,
                "score": score,
                "weight": weight,
                "contribution": round(
                    contribution,
                    2,
                ),
                "signal_level": signal_level,
            }
        )

    contributions.sort(
        key=lambda item: (
            item["score"],
            item["contribution"],
        ),
        reverse=True,
    )

    return contributions


# ============================================================================
# EXPLANATION ENGINE
# ============================================================================


def _humanize_model_name(
    model_name: str,
) -> str:
    """
    Convert internal engine names into readable security terms.
    """

    names = {
        "URL_PHISHING_ENGINE": "URL phishing analysis",
        "EMAIL_NLP_ENGINE": "email content analysis",
        "MESSAGE_NLP_ENGINE": "message analysis",
        "NLP_ENGINE": "natural-language analysis",
        "LOGIN_ANOMALY_ENGINE": "login anomaly analysis",
        "BEHAVIOUR_ANOMALY_ENGINE": "user behaviour analysis",
        "IMAGE_ENGINE": "image analysis",
        "VIDEO_ENGINE": "video analysis",
        "DEEPFAKE_ENGINE": "deepfake analysis",
        "IDENTITY_ENGINE": "identity analysis",
        "NETWORK_ENGINE": "network analysis",
        "MALWARE_ENGINE": "malware analysis",
        "EMBER_MALWARE_ENGINE": "EMBER malware model",
        "PHISHING_URL_ML_ENGINE": "trained URL phishing model",
        "PHISHING_EMAIL_ML_ENGINE": "trained email phishing model",
        "VOICE_ENGINE": "voice anti-spoofing analysis",
    }

    return names.get(
        model_name,
        model_name.replace(
            "_",
            " ",
        ).lower(),
    )


def generate_explanation(
    scores: dict[str, Any],
    final_score: float,
) -> str:
    """
    Generate human-readable explanation of the final risk score.
    """

    normalized = normalize_scores(
        scores
    )

    final_score = _safe_score(
        final_score
    )

    if not normalized:
        return (
            "No dedicated security detection engine "
            "returned a valid risk score."
        )

    critical_models = []
    high_models = []
    medium_models = []

    for model_name, score in normalized.items():

        readable_name = _humanize_model_name(
            model_name
        )

        if score >= 80:
            critical_models.append(
                f"{readable_name} ({score}/100)"
            )

        elif score >= 60:
            high_models.append(
                f"{readable_name} ({score}/100)"
            )

        elif score >= 40:
            medium_models.append(
                f"{readable_name} ({score}/100)"
            )

    severity = get_severity(
        final_score
    )

    if critical_models:

        return (
            f"Critical security indicators were detected by "
            f"{', '.join(critical_models)}. "
            f"The combined risk score is "
            f"{final_score}/100 ({severity})."
        )

    if high_models:

        return (
            f"High-risk security indicators were detected by "
            f"{', '.join(high_models)}. "
            f"The combined risk score is "
            f"{final_score}/100 ({severity})."
        )

    if medium_models:

        return (
            f"Moderate suspicious indicators were detected by "
            f"{', '.join(medium_models)}. "
            f"The combined risk score is "
            f"{final_score}/100 ({severity})."
        )

    return (
        f"No major high-risk indicators were detected by the "
        f"current security engines. "
        f"The combined risk score is "
        f"{final_score}/100 ({severity})."
    )


# ============================================================================
# RECOMMENDED RESPONSE ACTIONS
# ============================================================================


def get_recommended_actions(
    severity: str,
) -> list[str]:
    """
    Return recommended security actions based on severity.
    """

    severity = str(
        severity or "SAFE"
    ).upper()

    actions = {
        "SAFE": [
            "Allow",
            "Continue monitoring",
        ],

        "LOW": [
            "Monitor",
            "Alert user if behaviour continues",
        ],

        "MEDIUM": [
            "Increase monitoring",
            "Alert user",
            "Request additional verification",
        ],

        "HIGH": [
            "Block suspicious resource",
            "Alert user",
            "Alert administrator",
            "Strengthen authentication",
            "Increase monitoring",
        ],

        "CRITICAL": [
            "Block suspicious resource",
            "Quarantine suspicious content",
            "Revoke active sessions",
            "Strengthen authentication",
            "Alert administrator",
            "Escalate incident",
        ],
    }

    return list(
        actions.get(
            severity,
            actions["SAFE"],
        )
    )


# ============================================================================
# RISK FACTORS
# ============================================================================


def get_risk_factors(
    scores: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Return the most important risk factors in descending order.
    """

    normalized = normalize_scores(
        scores
    )

    factors = []

    for model_name, score in normalized.items():

        if score < 20:
            continue

        severity = get_severity(
            score
        )

        factors.append(
            {
                "model": model_name,
                "name": _humanize_model_name(
                    model_name
                ),
                "score": score,
                "severity": severity,
            }
        )

    factors.sort(
        key=lambda item: item["score"],
        reverse=True,
    )

    return factors


# ============================================================================
# COMPLETE RISK ANALYSIS
# ============================================================================


def analyze_risk(
    scores: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Main public API used by Guard threat detection.

    Returns:

        {
            "risk_score": 0-100,
            "severity": SAFE/LOW/MEDIUM/HIGH/CRITICAL,
            "explanation": "...",
            "recommended_actions": [...],
            "model_contributions": [...],
            "risk_factors": [...],
            "requires_incident": bool,
            "requires_immediate_response": bool,
        }
    """

    normalized_scores = normalize_scores(
        scores
    )

    final_score = calculate_risk_score(
        normalized_scores
    )

    severity = get_severity(
        final_score
    )

    explanation = generate_explanation(
        normalized_scores,
        final_score,
    )

    recommended_actions = get_recommended_actions(
        severity
    )

    model_contributions = get_model_contributions(
        normalized_scores
    )

    risk_factors = get_risk_factors(
        normalized_scores
    )

    requires_incident = (
        severity in AUTO_ESCALATE_SEVERITY
    )

    requires_immediate_response = (
        severity == "CRITICAL"
    )

    return {
        "risk_score": final_score,
        "severity": severity,
        "explanation": explanation,
        "recommended_actions": recommended_actions,
        "model_contributions": model_contributions,
        "risk_factors": risk_factors,
        "requires_incident": requires_incident,
        "requires_immediate_response": (
            requires_immediate_response
        ),
    }


# ============================================================================
# PUBLIC EXPORTS
# ============================================================================

__all__ = [
    "RISK_LEVELS",
    "MODEL_WEIGHTS",
    "AUTO_ESCALATE_SEVERITY",
    "get_severity",
    "normalize_scores",
    "calculate_weighted_average",
    "calculate_risk_score",
    "get_model_contributions",
    "generate_explanation",
    "get_recommended_actions",
    "get_risk_factors",
    "analyze_risk",
]