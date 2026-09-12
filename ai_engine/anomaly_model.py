"""
Behaviour and Anomaly Detection Engine.

Analyzes:
- Login activity
- Failed login attempts
- IP changes
- Device changes
- Location changes
- Suspicious access behaviour

This is an explainable anomaly-detection foundation.
A trained Isolation Forest / ML model can be integrated later.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------
# Risk levels
# ---------------------------------------------------------

def _clamp_score(score: float) -> float:
    return round(max(0.0, min(100.0, float(score))), 2)


def _get_severity(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "SAFE"


# ---------------------------------------------------------
# Main anomaly analysis
# ---------------------------------------------------------

def analyze_login(
    failed_attempts: int = 0,
    new_ip: bool = False,
    new_device: bool = False,
    new_location: bool = False,
    unusual_time: bool = False,
    impossible_travel: bool = False,
    suspicious_network: bool = False,
) -> dict[str, Any]:

    failed_attempts = max(0, int(failed_attempts))

    score = 0.0
    indicators: list[str] = []

    # -----------------------------------------------------
    # Failed login attempts
    # -----------------------------------------------------

    if failed_attempts >= 3:
        score += 25
        indicators.append(
            f"Multiple failed login attempts detected ({failed_attempts})"
        )

    if failed_attempts >= 5:
        score += 20
        indicators.append(
            "High number of consecutive failed login attempts"
        )

    if failed_attempts >= 10:
        score += 15
        indicators.append(
            "Possible brute-force login behaviour"
        )

    # -----------------------------------------------------
    # IP address
    # -----------------------------------------------------

    if new_ip:
        score += 20
        indicators.append(
            "Login originated from a previously unseen IP address"
        )

    # -----------------------------------------------------
    # Device
    # -----------------------------------------------------

    if new_device:
        score += 20
        indicators.append(
            "Login originated from a previously unseen device"
        )

    # -----------------------------------------------------
    # Location
    # -----------------------------------------------------

    if new_location:
        score += 15
        indicators.append(
            "Login originated from a previously unseen location"
        )

    # -----------------------------------------------------
    # Unusual login time
    # -----------------------------------------------------

    if unusual_time:
        score += 10
        indicators.append(
            "Login occurred at an unusual time for the user"
        )

    # -----------------------------------------------------
    # Impossible travel
    # -----------------------------------------------------

    if impossible_travel:
        score += 30
        indicators.append(
            "Potential impossible-travel behaviour detected"
        )

    # -----------------------------------------------------
    # Suspicious network
    # -----------------------------------------------------

    if suspicious_network:
        score += 25
        indicators.append(
            "Suspicious network characteristics detected"
        )

    # -----------------------------------------------------
    # Correlation rules
    # -----------------------------------------------------

    if failed_attempts >= 3 and new_ip:
        score += 10
        indicators.append(
            "Failed logins combined with a new IP address"
        )

    if failed_attempts >= 3 and new_device:
        score += 10
        indicators.append(
            "Failed logins combined with a new device"
        )

    if new_ip and new_device and new_location:
        score += 15
        indicators.append(
            "New IP, device and location detected together"
        )

    if impossible_travel and new_ip:
        score += 10
        indicators.append(
            "Impossible travel combined with a new IP"
        )

    if failed_attempts >= 5 and suspicious_network:
        score += 15
        indicators.append(
            "Repeated failed logins from a suspicious network"
        )

    # -----------------------------------------------------
    # Final score
    # -----------------------------------------------------

    score = _clamp_score(score)
    severity = _get_severity(score)

    # -----------------------------------------------------
    # Prediction
    # -----------------------------------------------------

    if score >= 80:
        prediction = "ACCOUNT_TAKEOVER_RISK"
    elif score >= 60:
        prediction = "HIGH_ANOMALY"
    elif score >= 40:
        prediction = "SUSPICIOUS_BEHAVIOUR"
    elif score >= 20:
        prediction = "LOW_ANOMALY"
    else:
        prediction = "NORMAL_BEHAVIOUR"

    # -----------------------------------------------------
    # Confidence
    # -----------------------------------------------------

    if score >= 80:
        confidence = 0.90
    elif score >= 60:
        confidence = 0.82
    elif score >= 40:
        confidence = 0.72
    elif score >= 20:
        confidence = 0.62
    else:
        confidence = 0.55

    # -----------------------------------------------------
    # Recommendation
    # -----------------------------------------------------

    if severity == "CRITICAL":
        recommendation = (
            "Immediately revoke suspicious sessions, strengthen authentication, "
            "alert the administrator and investigate the account."
        )

    elif severity == "HIGH":
        recommendation = (
            "Require additional authentication, alert the user/admin and "
            "monitor the account for further suspicious activity."
        )

    elif severity == "MEDIUM":
        recommendation = (
            "Monitor the account and consider additional authentication "
            "before allowing sensitive actions."
        )

    elif severity == "LOW":
        recommendation = (
            "Continue monitoring the account for repeated abnormal behaviour."
        )

    else:
        recommendation = (
            "No major abnormal login behaviour was detected by the current rules."
        )

    # -----------------------------------------------------
    # Features
    # -----------------------------------------------------

    features = {
        "failed_attempts": failed_attempts,
        "new_ip": bool(new_ip),
        "new_device": bool(new_device),
        "new_location": bool(new_location),
        "unusual_time": bool(unusual_time),
        "impossible_travel": bool(impossible_travel),
        "suspicious_network": bool(suspicious_network),
    }

    return {
        "analysis_type": "login_anomaly",
        "is_valid": True,
        "risk_score": score,
        "severity": severity,
        "prediction": prediction,
        "confidence": confidence,
        "indicators": indicators,
        "features": features,
        "recommendation": recommendation,
    }


# ---------------------------------------------------------
# Behaviour analysis
# ---------------------------------------------------------

def analyze_behavior(
    unusual_access: bool = False,
    unusual_resource_access: bool = False,
    unusual_request_volume: bool = False,
    new_device: bool = False,
    new_location: bool = False,
    suspicious_network: bool = False,
) -> dict[str, Any]:

    score = 0.0
    indicators: list[str] = []

    if unusual_access:
        score += 20
        indicators.append(
            "Unusual user access behaviour detected"
        )

    if unusual_resource_access:
        score += 25
        indicators.append(
            "Unusual resource access pattern detected"
        )

    if unusual_request_volume:
        score += 25
        indicators.append(
            "Abnormal request volume detected"
        )

    if new_device:
        score += 20
        indicators.append(
            "New device detected"
        )

    if new_location:
        score += 15
        indicators.append(
            "New location detected"
        )

    if suspicious_network:
        score += 25
        indicators.append(
            "Suspicious network behaviour detected"
        )

    if unusual_access and unusual_request_volume:
        score += 15
        indicators.append(
            "Unusual access combined with abnormal request volume"
        )

    if new_device and new_location and suspicious_network:
        score += 15
        indicators.append(
            "New device, location and suspicious network detected together"
        )

    score = _clamp_score(score)
    severity = _get_severity(score)

    if score >= 80:
        prediction = "CRITICAL_ANOMALY"
    elif score >= 60:
        prediction = "HIGH_ANOMALY"
    elif score >= 40:
        prediction = "SUSPICIOUS_BEHAVIOUR"
    elif score >= 20:
        prediction = "LOW_ANOMALY"
    else:
        prediction = "NORMAL_BEHAVIOUR"

    if score >= 80:
        confidence = 0.90
    elif score >= 60:
        confidence = 0.82
    elif score >= 40:
        confidence = 0.72
    elif score >= 20:
        confidence = 0.62
    else:
        confidence = 0.55

    if severity == "CRITICAL":
        recommendation = (
            "Immediately investigate the account, revoke suspicious sessions "
            "and strengthen authentication."
        )
    elif severity == "HIGH":
        recommendation = (
            "Alert the administrator and require additional authentication."
        )
    elif severity == "MEDIUM":
        recommendation = (
            "Monitor the user behaviour and investigate repeated anomalies."
        )
    elif severity == "LOW":
        recommendation = (
            "Continue monitoring for additional abnormal activity."
        )
    else:
        recommendation = (
            "No major behavioural anomaly was detected."
        )

    features = {
        "unusual_access": bool(unusual_access),
        "unusual_resource_access": bool(unusual_resource_access),
        "unusual_request_volume": bool(unusual_request_volume),
        "new_device": bool(new_device),
        "new_location": bool(new_location),
        "suspicious_network": bool(suspicious_network),
    }

    return {
        "analysis_type": "user_behavior",
        "is_valid": True,
        "risk_score": score,
        "severity": severity,
        "prediction": prediction,
        "confidence": confidence,
        "indicators": indicators,
        "features": features,
        "recommendation": recommendation,
    }


# ---------------------------------------------------------
# Compatibility wrappers
# ---------------------------------------------------------

def predict(**kwargs: Any) -> dict[str, Any]:
    """
    Generic prediction wrapper.
    """

    return analyze_login(**kwargs)


def analyze_anomaly(**kwargs: Any) -> dict[str, Any]:
    """
    Compatibility wrapper for anomaly analysis.
    """

    return analyze_login(**kwargs)