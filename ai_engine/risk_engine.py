RISK_LEVELS = {
    "SAFE": (0, 19),
    "LOW": (20, 39),
    "MEDIUM": (40, 59),
    "HIGH": (60, 79),
    "CRITICAL": (80, 100),
}


def get_severity(score):
    """
    Convert risk score (0-100) into severity level.
    """

    score = max(0, min(100, float(score)))

    for level, (minimum, maximum) in RISK_LEVELS.items():
        if minimum <= score <= maximum:
            return level

    return "SAFE"


def calculate_risk_score(scores):
    """
    Combine multiple AI/model scores into one final risk score.

    Example:
        {
            "phishing": 80,
            "nlp": 60,
            "anomaly": 40
        }
    """

    if not scores:
        return 0.0

    valid_scores = []

    for value in scores.values():
        try:
            value = float(value)
            value = max(0, min(100, value))
            valid_scores.append(value)
        except (TypeError, ValueError):
            continue

    if not valid_scores:
        return 0.0

    # Weighted average can be added later.
    final_score = sum(valid_scores) / len(valid_scores)

    return round(final_score, 2)


def generate_explanation(scores, final_score):
    """
    Generate a simple explainable reason for the final risk score.
    """

    if not scores:
        return "No sufficient security analysis data available."

    suspicious_models = [
        name
        for name, score in scores.items()
        if isinstance(score, (int, float)) and score >= 60
    ]

    if suspicious_models:
        models = ", ".join(suspicious_models)

        return (
            f"Elevated security risk detected based on analysis from: "
            f"{models}. Final risk score: {final_score}/100."
        )

    return (
        f"No major suspicious indicators were detected. "
        f"Final risk score: {final_score}/100."
    )


def get_recommended_actions(severity):
    """
    Return recommended security response based on severity.
    """

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

    return actions.get(severity, ["Monitor"])


def analyze_risk(scores):
    """
    Main risk-engine function.

    Returns:
        {
            "risk_score": 75.0,
            "severity": "HIGH",
            "explanation": "...",
            "recommended_actions": [...]
        }
    """

    final_score = calculate_risk_score(scores)
    severity = get_severity(final_score)
    explanation = generate_explanation(scores, final_score)
    recommended_actions = get_recommended_actions(severity)

    return {
        "risk_score": final_score,
        "severity": severity,
        "explanation": explanation,
        "recommended_actions": recommended_actions,
    }