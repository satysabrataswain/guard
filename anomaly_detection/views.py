from __future__ import annotations

from typing import Any

from django.db import transaction
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.utils import get_client_ip
from audit_logs.models import AuditLog

from ai_engine.anomaly_model import (
    analyze_behavior,
    analyze_login,
)
from ai_engine.risk_engine import analyze_risk

from incidents.models import (
    Incident,
    IncidentEvidence,
    ResponseAction,
)

from threat_detection.models import (
    Threat,
    ThreatAnalysis,
    ThreatEvidence,
)

from .models import (
    Anomaly,
    LoginActivity,
    UserBehaviour,
)

from .serializers import (
    AnomalySerializer,
    LoginActivitySerializer,
    UserBehaviourSerializer,
)


# ============================================================
# HELPERS
# ============================================================

def _safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default

    return round(
        max(
            0.0,
            min(
                100.0,
                number,
            ),
        ),
        2,
    )


def _normalize_confidence(
    value: Any,
) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.0

    # Convert 0-1 confidence into 0-100.
    if 0.0 <= confidence <= 1.0:
        confidence *= 100.0

    return round(
        max(
            0.0,
            min(
                100.0,
                confidence,
            ),
        ),
        2,
    )


def _bool_value(
    value: Any,
) -> bool:
    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        return bool(value)

    if isinstance(value, str):
        return value.strip().lower() in {
            "1",
            "true",
            "yes",
            "y",
            "on",
        }

    return False


# ============================================================
# THREAT CREATION
# ============================================================

def _create_threat(
    user,
    source_type: str,
    input_data: dict,
    result: dict,
    risk: dict,
) -> Threat:
    score = _safe_float(
        risk.get(
            "risk_score",
            0,
        )
    )

    severity = str(
        risk.get(
            "severity",
            "SAFE",
        )
    ).upper()

    valid_severities = dict(
        Threat.SEVERITY_CHOICES
    )

    if severity not in valid_severities:
        severity = "SAFE"

    indicators = result.get(
        "indicators",
        [],
    )

    if not isinstance(
        indicators,
        list,
    ):
        indicators = []

    clean_indicators = []

    for indicator in indicators:
        if indicator is None:
            continue

        text = str(
            indicator
        ).strip()

        if text and text not in clean_indicators:
            clean_indicators.append(text)

    explanation = str(
        risk.get(
            "explanation",
            "",
        )
    )

    if clean_indicators:
        indicator_text = "; ".join(
            clean_indicators[:10]
        )

        if explanation:
            explanation = (
                f"{explanation} "
                f"Key indicators: {indicator_text}"
            )
        else:
            explanation = (
                "Anomaly indicators detected: "
                f"{indicator_text}"
            )

    return Threat.objects.create(
        user=user,
        threat_type="ANOMALY",
        source_type=source_type,
        input_data=str(input_data),
        risk_score=score,
        severity=severity,
        status="DETECTED",
        explanation=explanation,
    )


def _save_threat_analysis(
    threat: Threat,
    model_name: str,
    result: dict,
) -> None:
    if not isinstance(
        result,
        dict,
    ):
        result = {}

    score = _safe_float(
        result.get(
            "risk_score",
            result.get(
                "score",
                0,
            ),
        )
    )

    confidence = _normalize_confidence(
        result.get(
            "confidence",
            0,
        )
    )

    prediction = str(
        result.get(
            "prediction",
            "UNKNOWN",
        )
    )[:100]

    ThreatAnalysis.objects.create(
        threat=threat,
        model_name=model_name,
        model_version="1.0-rule-engine",
        prediction=prediction,
        confidence=confidence,
        score=score,
        analysis_result=result,
    )

    indicators = result.get(
        "indicators",
        [],
    )

    if not isinstance(
        indicators,
        list,
    ):
        return

    evidence_objects = []

    for indicator in indicators:
        if indicator is None:
            continue

        text = str(
            indicator
        ).strip()

        if not text:
            continue

        evidence_objects.append(
            ThreatEvidence(
                threat=threat,
                evidence_type=model_name,
                evidence_value=text,
                risk_contribution=score,
            )
        )

    if evidence_objects:
        ThreatEvidence.objects.bulk_create(
            evidence_objects
        )


# ============================================================
# INCIDENT CREATION
# ============================================================

def _create_incident(
    threat: Threat,
    risk: dict,
) -> Incident | None:

    if threat.severity not in {
        "HIGH",
        "CRITICAL",
    }:
        return None

    incident = Incident.objects.create(
        incident_type="ANOMALY",
        title=(
            f"{threat.severity} "
            "Behaviour/Login Anomaly"
        ),
        description=threat.explanation,
        severity=threat.severity,
        status="OPEN",
        risk_score=threat.risk_score,
        created_by=threat.user,
        source_type=threat.source_type,
        source_id=threat.id,
    )

    for evidence in threat.evidence.all():
        IncidentEvidence.objects.create(
            incident=incident,
            evidence_type=evidence.evidence_type,
            evidence_value=evidence.evidence_value,
            risk_contribution=evidence.risk_contribution,
        )

    action_mapping = {
        "Revoke active sessions": "REVOKE_SESSION",
        "Strengthen authentication": "STRENGTHEN_AUTH",
        "Alert user": "ALERT_USER",
        "Alert administrator": "ALERT_ADMIN",
        "Escalate incident": "ESCALATE",
        "Monitor": "MONITOR",
        "Increase monitoring": "MONITOR",
        "Request additional verification": (
            "STRENGTHEN_AUTH"
        ),
        "Alert user if behaviour continues": (
            "ALERT_USER"
        ),
    }

    recommended_actions = risk.get(
        "recommended_actions",
        [],
    )

    if not isinstance(
        recommended_actions,
        list,
    ):
        recommended_actions = []

    for action in recommended_actions:
        action_type = action_mapping.get(action)

        if not action_type:
            continue

        ResponseAction.objects.create(
            incident=incident,
            action_type=action_type,
            description=(
                "Recommended by automated "
                f"anomaly analysis: {action}"
            ),
        )

    return incident


# ============================================================
# LOGIN ANALYSIS
# ============================================================

class LoginAnalysisView(APIView):
    permission_classes = [
        IsAuthenticated
    ]

    @transaction.atomic
    def post(
        self,
        request,
    ):
        data = request.data

        # ----------------------------------------------------
        # Historical login information
        # ----------------------------------------------------

        previous_logins = (
            LoginActivity.objects
            .filter(
                user=request.user
            )
            .order_by("-created_at")
        )

        recent_failed_attempts = (
            previous_logins
            .filter(
                status="FAILED"
            )
            .count()
        )

        latest_login = previous_logins.first()

        # ----------------------------------------------------
        # failed_attempts
        # ----------------------------------------------------

        if "failed_attempts" in data:
            failed_attempts = data.get(
                "failed_attempts"
            )

            try:
                failed_attempts = int(
                    failed_attempts
                )
            except (
                TypeError,
                ValueError,
            ):
                return Response(
                    {
                        "detail": (
                            "failed_attempts "
                            "must be an integer."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if failed_attempts < 0:
                return Response(
                    {
                        "detail": (
                            "failed_attempts "
                            "cannot be negative."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            failed_attempts = recent_failed_attempts

        # ----------------------------------------------------
        # Current request values
        # ----------------------------------------------------

        current_ip = (
            data.get("ip_address")
            or get_client_ip(request)
        )

        current_device = (
            data.get("device_id")
            or ""
        )

        current_location = (
            data.get("location")
            or ""
        )

        # ----------------------------------------------------
        # Infer new IP/device/location from history
        # ----------------------------------------------------

        if "new_ip" in data:
            new_ip = _bool_value(
                data.get("new_ip")
            )
        else:
            new_ip = bool(
                latest_login
                and current_ip
                and latest_login.ip_address
                and current_ip != latest_login.ip_address
            )

        if "new_device" in data:
            new_device = _bool_value(
                data.get("new_device")
            )
        else:
            new_device = bool(
                latest_login
                and current_device
                and latest_login.device_id
                and current_device != latest_login.device_id
            )

        if "new_location" in data:
            new_location = _bool_value(
                data.get("new_location")
            )
        else:
            new_location = bool(
                latest_login
                and current_location
                and latest_login.location
                and current_location != latest_login.location
            )

        analysis_input = {
            "failed_attempts": failed_attempts,
            "new_ip": new_ip,
            "new_device": new_device,
            "new_location": new_location,
            "unusual_time": _bool_value(
                data.get(
                    "unusual_time",
                    False,
                )
            ),
            "impossible_travel": _bool_value(
                data.get(
                    "impossible_travel",
                    False,
                )
            ),
            "suspicious_network": _bool_value(
                data.get(
                    "suspicious_network",
                    False,
                )
            ),
        }

        # ----------------------------------------------------
        # AI / anomaly engine
        # ----------------------------------------------------

        result = analyze_login(
            **analysis_input
        )

        if not isinstance(
            result,
            dict,
        ):
            result = {}

        model_score = _safe_float(
            result.get(
                "risk_score",
                result.get(
                    "score",
                    0,
                ),
            )
        )

        risk = analyze_risk(
            {
                "LOGIN_ANOMALY_ENGINE":
                    model_score
            }
        )

        # ----------------------------------------------------
        # Threat
        # ----------------------------------------------------

        threat = _create_threat(
            user=request.user,
            source_type="LOGIN",
            input_data=analysis_input,
            result=result,
            risk=risk,
        )

        _save_threat_analysis(
            threat=threat,
            model_name="LOGIN_ANOMALY_ENGINE",
            result=result,
        )

        # ----------------------------------------------------
        # Recalculate incident after complete analysis
        # ----------------------------------------------------

        incident = _create_incident(
            threat=threat,
            risk=risk,
        )

        # ----------------------------------------------------
        # Login activity
        # ----------------------------------------------------

        status_value = str(
            data.get(
                "status",
                "",
            )
        ).strip().upper()

        if status_value not in {
            "SUCCESS",
            "FAILED",
            "BLOCKED",
        }:
            successful = _bool_value(
                data.get(
                    "successful",
                    True,
                )
            )

            status_value = (
                "SUCCESS"
                if successful
                else "FAILED"
            )

        failure_reason = str(
            data.get(
                "failure_reason",
                "",
            )
        )

        if (
            status_value in {
                "FAILED",
                "BLOCKED",
            }
            and not failure_reason
        ):
            failure_reason = "Anomaly analysis request"

        login_activity = LoginActivity.objects.create(
            user=request.user,
            ip_address=current_ip,
            user_agent=(
                data.get("user_agent")
                or request.META.get(
                    "HTTP_USER_AGENT",
                    "",
                )
            ),
            location=current_location,
            device_id=current_device,
            status=status_value,
            failure_reason=failure_reason,
        )

        # ----------------------------------------------------
        # Anomaly record
        # ----------------------------------------------------

        anomaly = Anomaly.objects.create(
            user=request.user,
            anomaly_type="LOGIN",
            risk_score=threat.risk_score,
            severity=threat.severity,
            explanation=threat.explanation,
        )

        # ----------------------------------------------------
        # Audit
        # ----------------------------------------------------

        AuditLog.objects.create(
            user=request.user,
            action="LOGIN_ANOMALY_ANALYZED",
            ip_address=get_client_ip(request),
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                "Login anomaly analysis completed. "
                f"Threat ID: {threat.id}; "
                f"score={threat.risk_score}; "
                f"severity={threat.severity}"
            ),
            status="SUCCESS",
        )

        # ----------------------------------------------------
        # Response
        # ----------------------------------------------------

        response_data = {
            "message": (
                "Login anomaly analysis completed."
            ),
            "login_activity_id": (
                login_activity.id
            ),
            "anomaly_id": anomaly.id,
            "anomaly": {
                "id": anomaly.id,
                "type": anomaly.anomaly_type,
                "risk_score": anomaly.risk_score,
                "severity": anomaly.severity,
                "status": anomaly.status,
                "explanation": anomaly.explanation,
            },
            "threat_id": threat.id,
            "risk_score": threat.risk_score,
            "severity": threat.severity,
            "prediction": result.get(
                "prediction",
                "UNKNOWN",
            ),
            "confidence": _normalize_confidence(
                result.get(
                    "confidence",
                    0,
                )
            ),
            "indicators": result.get(
                "indicators",
                [],
            ),
            "explanation": threat.explanation,
            "recommended_actions": risk.get(
                "recommended_actions",
                [],
            ),
        }

        if incident:
            response_data["incident"] = {
                "id": incident.id,
                "severity": incident.severity,
                "status": incident.status,
            }

        return Response(
            response_data,
            status=status.HTTP_201_CREATED,
        )


# ============================================================
# BEHAVIOUR ANALYSIS
# ============================================================

class BehaviourAnalysisView(APIView):
    permission_classes = [
        IsAuthenticated
    ]

    @transaction.atomic
    def post(
        self,
        request,
    ):
        data = request.data

        analysis_input = {
            "unusual_access": _bool_value(
                data.get(
                    "unusual_access",
                    False,
                )
            ),
            "unusual_resource_access": _bool_value(
                data.get(
                    "unusual_resource_access",
                    False,
                )
            ),
            "unusual_request_volume": _bool_value(
                data.get(
                    "unusual_request_volume",
                    False,
                )
            ),
            "new_device": _bool_value(
                data.get(
                    "new_device",
                    False,
                )
            ),
            "new_location": _bool_value(
                data.get(
                    "new_location",
                    False,
                )
            ),
            "suspicious_network": _bool_value(
                data.get(
                    "suspicious_network",
                    False,
                )
            ),
        }

        result = analyze_behavior(
            **analysis_input
        )

        if not isinstance(
            result,
            dict,
        ):
            result = {}

        model_score = _safe_float(
            result.get(
                "risk_score",
                result.get(
                    "score",
                    0,
                ),
            )
        )

        risk = analyze_risk(
            {
                "BEHAVIOUR_ANOMALY_ENGINE":
                    model_score
            }
        )

        threat = _create_threat(
            user=request.user,
            source_type="DEVICE",
            input_data=analysis_input,
            result=result,
            risk=risk,
        )

        _save_threat_analysis(
            threat=threat,
            model_name="BEHAVIOUR_ANOMALY_ENGINE",
            result=result,
        )

        incident = _create_incident(
            threat=threat,
            risk=risk,
        )

        activity_type = str(
            data.get(
                "activity_type",
                "OTHER",
            )
        ).upper()

        valid_activity_types = {
            "LOGIN",
            "LOGOUT",
            "ACCESS",
            "NETWORK",
            "DEVICE",
            "OTHER",
        }

        if activity_type not in valid_activity_types:
            activity_type = "OTHER"

        behaviour = UserBehaviour.objects.create(
            user=request.user,
            activity_type=activity_type,
            ip_address=data.get(
                "ip_address"
            ),
            user_agent=data.get(
                "user_agent",
                "",
            ),
            location=data.get(
                "location",
                "",
            ),
            device_id=data.get(
                "device_id",
                "",
            ),
            activity_data={
                "request_data": dict(data),
                "analysis_input": analysis_input,
                "analysis_result": result,
            },
        )

        anomaly = Anomaly.objects.create(
            user=request.user,
            anomaly_type="BEHAVIOUR",
            risk_score=threat.risk_score,
            severity=threat.severity,
            explanation=threat.explanation,
        )

        AuditLog.objects.create(
            user=request.user,
            action="BEHAVIOUR_ANOMALY_ANALYZED",
            ip_address=get_client_ip(request),
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                "Behaviour anomaly analysis completed. "
                f"Threat ID: {threat.id}; "
                f"score={threat.risk_score}; "
                f"severity={threat.severity}"
            ),
            status="SUCCESS",
        )

        response_data = {
            "message": (
                "Behaviour anomaly analysis completed."
            ),
            "behaviour_id": behaviour.id,
            "anomaly_id": anomaly.id,
            "threat_id": threat.id,
            "risk_score": threat.risk_score,
            "severity": threat.severity,
            "prediction": result.get(
                "prediction",
                "UNKNOWN",
            ),
            "confidence": _normalize_confidence(
                result.get(
                    "confidence",
                    0,
                )
            ),
            "indicators": result.get(
                "indicators",
                [],
            ),
            "explanation": threat.explanation,
            "recommended_actions": risk.get(
                "recommended_actions",
                [],
            ),
        }

        if incident:
            response_data["incident"] = {
                "id": incident.id,
                "severity": incident.severity,
                "status": incident.status,
            }

        return Response(
            response_data,
            status=status.HTTP_201_CREATED,
        )


# ============================================================
# LOGIN ACTIVITY CREATE
# ============================================================

class LoginActivityCreateView(APIView):
    permission_classes = [
        IsAuthenticated
    ]

    @transaction.atomic
    def post(
        self,
        request,
    ):
        data = request.data

        status_value = str(
            data.get(
                "status",
                "SUCCESS",
            )
        ).strip().upper()

        if status_value not in {
            "SUCCESS",
            "FAILED",
            "BLOCKED",
        }:
            return Response(
                {
                    "detail": (
                        "status must be "
                        "SUCCESS, FAILED, "
                        "or BLOCKED."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        activity = LoginActivity.objects.create(
            user=request.user,
            ip_address=(
                data.get("ip_address")
                or get_client_ip(request)
            ),
            user_agent=(
                data.get("user_agent")
                or request.META.get(
                    "HTTP_USER_AGENT",
                    "",
                )
            ),
            location=data.get(
                "location",
                "",
            ),
            device_id=data.get(
                "device_id",
                "",
            ),
            status=status_value,
            failure_reason=data.get(
                "failure_reason",
                "",
            ),
        )

        return Response(
            LoginActivitySerializer(
                activity
            ).data,
            status=status.HTTP_201_CREATED,
        )


# ============================================================
# LOGIN ACTIVITY HISTORY
# ============================================================

class LoginActivityHistoryView(
    generics.ListAPIView
):
    serializer_class = LoginActivitySerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):
        return (
            LoginActivity.objects
            .filter(
                user=self.request.user
            )
            .order_by(
                "-created_at"
            )
        )


# ============================================================
# LOGIN ACTIVITY DETAIL
# ============================================================

class LoginActivityDetailView(
    generics.RetrieveAPIView
):
    serializer_class = LoginActivitySerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):
        return LoginActivity.objects.filter(
            user=self.request.user
        )


# ============================================================
# BEHAVIOUR HISTORY
# ============================================================

class BehaviourHistoryView(
    generics.ListAPIView
):
    serializer_class = UserBehaviourSerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):
        return (
            UserBehaviour.objects
            .filter(
                user=self.request.user
            )
            .order_by(
                "-created_at"
            )
        )


# ============================================================
# BEHAVIOUR DETAIL
# ============================================================

class BehaviourDetailView(
    generics.RetrieveAPIView
):
    serializer_class = UserBehaviourSerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):
        return UserBehaviour.objects.filter(
            user=self.request.user
        )


# ============================================================
# ANOMALY HISTORY
# ============================================================

class AnomalyHistoryView(
    generics.ListAPIView
):
    serializer_class = AnomalySerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):
        return (
            Anomaly.objects
            .filter(
                user=self.request.user
            )
            .order_by(
                "-detected_at"
            )
        )


# ============================================================
# ANOMALY DETAIL
# ============================================================

class AnomalyDetailView(
    generics.RetrieveAPIView
):
    serializer_class = AnomalySerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):
        return Anomaly.objects.filter(
            user=self.request.user
        )