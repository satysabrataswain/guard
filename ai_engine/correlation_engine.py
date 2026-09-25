"""
GUARD Unified Multi-Source Correlation Engine

This module combines security signals from multiple sources
into one explainable risk assessment.

Supported sources:
    URL
    EMAIL
    MESSAGE
    IMAGE
    VIDEO
    LOGIN
    DEVICE
    NETWORK
    FILE

The goal is to correlate multiple weak/strong signals instead
of treating every scan as an isolated event.
"""

from __future__ import annotations

from typing import Any


# ============================================================================
# SOURCE WEIGHTS
# ============================================================================

SOURCE_WEIGHTS = {
    "URL": 1.20,
    "EMAIL": 1.15,
    "MESSAGE": 1.10,
    "IMAGE": 1.15,
    "VIDEO": 1.25,
    "LOGIN": 1.25,
    "DEVICE": 1.20,
    "NETWORK": 1.30,
    "FILE": 1.30,
    "OTHER": 1.00,
}


# ============================================================================
# CORRELATION BOOSTS
# ============================================================================

# When multiple different source categories are suspicious,
# GUARD increases the final risk because the signals support
# each other.

CORRELATION_BOOSTS = {
    2: 5.0,
    3: 10.0,
    4: 15.0,
    5: 20.0,
    6: 25.0,
}


# ============================================================================
# HIGH-RISK SOURCE COMBINATIONS
# ============================================================================

# These combinations represent stronger attack patterns.

HIGH_RISK_COMBINATIONS = [
    (
        {"URL", "EMAIL"},
        "Phishing URL and suspicious email signals are correlated.",
    ),
    (
        {"EMAIL", "LOGIN"},
        "Suspicious email activity is correlated with abnormal login behaviour.",
    ),
    (
        {"URL", "LOGIN"},
        "Suspicious URL activity is correlated with abnormal authentication activity.",
    ),
    (
        {"EMAIL", "IMAGE"},
        "Email and image/identity signals indicate possible impersonation.",
    ),
    (
        {"EMAIL", "VIDEO"},
        "Email and video signals indicate possible social-engineering or impersonation activity.",
    ),
    (
        {"IMAGE", "VIDEO"},
        "Multiple media sources indicate possible manipulation or deepfake activity.",
    ),
    (
        {"LOGIN", "NETWORK"},
        "Authentication anomaly is correlated with suspicious network behaviour.",
    ),
    (
        {"LOGIN", "DEVICE"},
        "Authentication anomaly is correlated with suspicious device activity.",
    ),
    (
        {"NETWORK", "DEVICE"},
        "Network and device anomalies indicate potentially coordinated malicious activity.",
    ),
    (
        {"URL", "EMAIL", "LOGIN"},
        "Phishing, email and authentication signals form a strong possible account-takeover pattern.",
    ),
    (
        {"EMAIL", "LOGIN", "NETWORK"},
        "Email, authentication and network anomalies form a coordinated attack pattern.",
    ),
    (
        {"URL", "LOGIN", "NETWORK"},
        "Suspicious URL, login and network activity indicate possible credential compromise.",
    ),
]


# ============================================================================
# HELPERS
# ============================================================================


def _clamp(
    value: Any,
    minimum: float = 0.0,
    maximum: float = 100.0,
) -> float:
    """
    Safely clamp a numeric value into a fixed range.
    """

    try:
        value = float(value)
    except (TypeError, ValueError):
        value = minimum

    return round(
        max(
            minimum,
            min(
                maximum,
                value,
            ),
        ),
        2,
    )


def _normalize_score(
    value: Any,
) -> float:
    """
    Normalize score to 0-100.
    """

    return _clamp(value)


def _normalize_source(
    source: Any,
) -> str:
    """
    Normalize source name.
    """

    if source is None:
        return "OTHER"

    source = str(source).strip().upper()

    return source or "OTHER"


def _source_weight(
    source: str,
) -> float:
    """
    Return source-specific correlation weight.
    """

    return float(
        SOURCE_WEIGHTS.get(
            source,
            SOURCE_WEIGHTS["OTHER"],
        )
    )


def _severity(
    score: float,
) -> str:
    """
    Convert final risk score to GUARD severity.
    """

    score = _clamp(score)

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
# SIGNAL NORMALIZATION
# ============================================================================


def normalize_signals(
    signals: Any,
) -> list[dict[str, Any]]:
    """
    Normalize different signal input formats.

    Accepted format:

        [
            {
                "source": "URL",
                "score": 80,
                "indicators": [
                    "Suspicious domain"
                ]
            },
            {
                "source": "EMAIL",
                "score": 70,
                "indicators": [
                    "Urgent payment request"
                ]
            }
        ]

    Also supports:

        {
            "URL": 80,
            "EMAIL": 70
        }
    """

    normalized = []

    # ------------------------------------------------------------------
    # Dictionary format
    # ------------------------------------------------------------------

    if isinstance(signals, dict):

        for source, raw_value in signals.items():

            if isinstance(raw_value, dict):

                score = raw_value.get(
                    "score",
                    raw_value.get(
                        "risk_score",
                        0,
                    ),
                )

                indicators = raw_value.get(
                    "indicators",
                    [],
                )

            else:

                score = raw_value
                indicators = []

            normalized.append(
                {
                    "source": _normalize_source(source),
                    "score": _normalize_score(score),
                    "indicators": (
                        indicators
                        if isinstance(indicators, list)
                        else []
                    ),
                }
            )

        return normalized

    # ------------------------------------------------------------------
    # List format
    # ------------------------------------------------------------------

    if isinstance(signals, list):

        for item in signals:

            if not isinstance(item, dict):
                continue

            source = _normalize_source(
                item.get(
                    "source",
                    item.get(
                        "source_type",
                        "OTHER",
                    ),
                )
            )

            score = item.get(
                "score",
                item.get(
                    "risk_score",
                    0,
                ),
            )

            indicators = item.get(
                "indicators",
                [],
            )

            if not isinstance(
                indicators,
                list,
            ):
                indicators = []

            normalized.append(
                {
                    "source": source,
                    "score": _normalize_score(score),
                    "indicators": indicators,
                }
            )

    return normalized


# ============================================================================
# SOURCE AGGREGATION
# ============================================================================


def aggregate_sources(
    signals: list[dict[str, Any]],
) -> dict[str, float]:
    """
    Aggregate multiple signals belonging to the same source.

    If several events come from the same source, the strongest
    score is retained while avoiding uncontrolled score inflation.
    """

    source_scores: dict[str, list[float]] = {}

    for signal in signals:

        source = _normalize_source(
            signal.get(
                "source",
                "OTHER",
            )
        )

        score = _normalize_score(
            signal.get(
                "score",
                0,
            )
        )

        source_scores.setdefault(
            source,
            [],
        ).append(score)

    aggregated = {}

    for source, scores in source_scores.items():

        if not scores:
            continue

        strongest = max(scores)

        if len(scores) == 1:

            aggregated[source] = round(
                strongest,
                2,
            )

            continue

        # Multiple signals from same source:
        # strongest signal gets primary influence,
        # remaining signals provide a small supporting boost.

        supporting_scores = sorted(
            scores,
            reverse=True,
        )[1:]

        support_boost = (
            sum(supporting_scores[:3])
            * 0.10
        )

        aggregated[source] = _clamp(
            strongest + support_boost
        )

    return aggregated


# ============================================================================
# CROSS-SOURCE CORRELATION
# ============================================================================


def detect_correlated_sources(
    source_scores: dict[str, float],
) -> list[dict[str, Any]]:
    """
    Identify suspicious combinations across different source types.

    Only sources with a score >= 40 are considered suspicious
    enough to participate in correlation.
    """

    suspicious_sources = {
        source
        for source, score in source_scores.items()
        if score >= 40
    }

    correlations = []

    for required_sources, explanation in HIGH_RISK_COMBINATIONS:

        if required_sources.issubset(
            suspicious_sources
        ):

            involved_scores = [
                source_scores[source]
                for source in required_sources
                if source in source_scores
            ]

            correlations.append(
                {
                    "sources": sorted(
                        required_sources
                    ),
                    "average_score": round(
                        sum(involved_scores)
                        / len(involved_scores),
                        2,
                    ),
                    "explanation": explanation,
                }
            )

    return correlations


# ============================================================================
# CORRELATION SCORE
# ============================================================================


def calculate_correlation_score(
    signals: Any,
) -> dict[str, Any]:
    """
    Calculate a unified cross-source risk score.

    The score combines:

        1. Weighted source risk
        2. Number of suspicious source categories
        3. Cross-source attack-pattern boosts
        4. Strongest individual signal

    This prevents a dangerous signal from being hidden by
    several low-risk signals.
    """

    normalized_signals = normalize_signals(
        signals
    )

    if not normalized_signals:

        return {
            "risk_score": 0.0,
            "severity": "SAFE",
            "source_scores": {},
            "suspicious_sources": [],
            "correlations": [],
            "correlation_boost": 0.0,
        }

    source_scores = aggregate_sources(
        normalized_signals
    )

    if not source_scores:

        return {
            "risk_score": 0.0,
            "severity": "SAFE",
            "source_scores": {},
            "suspicious_sources": [],
            "correlations": [],
            "correlation_boost": 0.0,
        }

    # ------------------------------------------------------------------
    # Weighted source average
    # ------------------------------------------------------------------

    weighted_total = 0.0
    total_weight = 0.0

    for source, score in source_scores.items():

        weight = _source_weight(
            source
        )

        weighted_total += (
            score * weight
        )

        total_weight += weight

    if total_weight <= 0:

        weighted_average = 0.0

    else:

        weighted_average = (
            weighted_total
            / total_weight
        )

    # ------------------------------------------------------------------
    # Suspicious source categories
    # ------------------------------------------------------------------

    suspicious_sources = sorted(
        source
        for source, score in source_scores.items()
        if score >= 40
    )

    suspicious_count = len(
        suspicious_sources
    )

    # ------------------------------------------------------------------
    # Number-of-source correlation boost
    # ------------------------------------------------------------------

    correlation_boost = CORRELATION_BOOSTS.get(
        suspicious_count,
        0.0,
    )

    if suspicious_count > 6:

        correlation_boost = 25.0

    # ------------------------------------------------------------------
    # Specific attack-pattern correlations
    # ------------------------------------------------------------------

    correlations = detect_correlated_sources(
        source_scores
    )

    pattern_boost = min(
        len(correlations) * 5.0,
        20.0,
    )

    correlation_boost += pattern_boost

    # ------------------------------------------------------------------
    # Strongest signal
    # ------------------------------------------------------------------

    strongest_signal = max(
        source_scores.values()
    )

    # ------------------------------------------------------------------
    # Final score
    # ------------------------------------------------------------------

    final_score = (
        weighted_average * 0.55
        + strongest_signal * 0.25
        + correlation_boost * 0.20
    )

    # ------------------------------------------------------------------
    # Strong signal protection
    # ------------------------------------------------------------------

    if strongest_signal >= 90:

        final_score = max(
            final_score,
            strongest_signal * 0.85,
        )

    elif strongest_signal >= 80:

        final_score = max(
            final_score,
            strongest_signal * 0.75,
        )

    elif strongest_signal >= 70:

        final_score = max(
            final_score,
            strongest_signal * 0.70,
        )

    final_score = _clamp(
        final_score
    )

    severity = _severity(
        final_score
    )

    return {
        "risk_score": final_score,
        "severity": severity,
        "source_scores": source_scores,
        "suspicious_sources": suspicious_sources,
        "correlations": correlations,
        "correlation_boost": round(
            correlation_boost,
            2,
        ),
        "strongest_signal": strongest_signal,
        "weighted_average": round(
            weighted_average,
            2,
        ),
    }


# ============================================================================
# EXPLAINABILITY
# ============================================================================


def generate_correlation_explanation(
    result: dict[str, Any],
) -> str:
    """
    Generate human-readable explanation for the
    unified correlation result.
    """

    if not isinstance(
        result,
        dict,
    ):
        return (
            "No correlation result was available."
        )

    risk_score = _clamp(
        result.get(
            "risk_score",
            0,
        )
    )

    severity = str(
        result.get(
            "severity",
            "SAFE",
        )
    ).upper()

    suspicious_sources = result.get(
        "suspicious_sources",
        [],
    )

    correlations = result.get(
        "correlations",
        [],
    )

    if not suspicious_sources:

        return (
            f"GUARD found no significant cross-source "
            f"correlation. Unified risk score: "
            f"{risk_score}/100 ({severity})."
        )

    source_text = ", ".join(
        suspicious_sources
    )

    explanation = (
        f"GUARD correlated suspicious signals from "
        f"{source_text}. "
    )

    if correlations:

        pattern_text = " ".join(
            item.get(
                "explanation",
                "",
            )
            for item in correlations
            if isinstance(item, dict)
        )

        if pattern_text:

            explanation += (
                f"{pattern_text} "
            )

    explanation += (
        f"Unified risk score: "
        f"{risk_score}/100 ({severity})."
    )

    return explanation.strip()


# ============================================================================
# EVIDENCE
# ============================================================================


def collect_correlation_evidence(
    signals: Any,
) -> list[dict[str, Any]]:
    """
    Convert source indicators into unified evidence.

    Each evidence item keeps the originating source so the
    dashboard can explain where the signal came from.
    """

    normalized = normalize_signals(
        signals
    )

    evidence = []

    for signal in normalized:

        source = signal.get(
            "source",
            "OTHER",
        )

        score = _normalize_score(
            signal.get(
                "score",
                0,
            )
        )

        indicators = signal.get(
            "indicators",
            [],
        )

        if not indicators:

            evidence.append(
                {
                    "source": source,
                    "evidence_type": (
                        "SOURCE_RISK_SIGNAL"
                    ),
                    "evidence": (
                        f"{source} produced a "
                        f"risk score of {score}/100."
                    ),
                    "risk_contribution": score,
                }
            )

            continue

        for indicator in indicators:

            if indicator is None:
                continue

            text = str(
                indicator
            ).strip()

            if not text:
                continue

            evidence.append(
                {
                    "source": source,
                    "evidence_type": (
                        "SECURITY_INDICATOR"
                    ),
                    "evidence": text,
                    "risk_contribution": score,
                }
            )

    return evidence


# ============================================================================
# MAIN PUBLIC API
# ============================================================================


def correlate_threat_signals(
    signals: Any,
) -> dict[str, Any]:
    """
    Main public GUARD correlation API.

    Example:

        result = correlate_threat_signals(
            [
                {
                    "source": "URL",
                    "score": 85,
                    "indicators": [
                        "Suspicious domain"
                    ],
                },
                {
                    "source": "EMAIL",
                    "score": 75,
                    "indicators": [
                        "Urgent credential request"
                    ],
                },
                {
                    "source": "LOGIN",
                    "score": 80,
                    "indicators": [
                        "New device login"
                    ],
                },
            ]
        )

    Returns:

        {
            "risk_score": ...,
            "severity": ...,
            "explanation": ...,
            "source_scores": ...,
            "suspicious_sources": ...,
            "correlations": ...,
            "evidence": ...,
        }
    """

    result = calculate_correlation_score(
        signals
    )

    result["explanation"] = (
        generate_correlation_explanation(
            result
        )
    )

    result["evidence"] = (
        collect_correlation_evidence(
            signals
        )
    )

    return result


__all__ = [
    "SOURCE_WEIGHTS",
    "CORRELATION_BOOSTS",
    "HIGH_RISK_COMBINATIONS",
    "normalize_signals",
    "aggregate_sources",
    "detect_correlated_sources",
    "calculate_correlation_score",
    "generate_correlation_explanation",
    "collect_correlation_evidence",
    "correlate_threat_signals",
]