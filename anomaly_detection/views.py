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


def _safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    try:
        number = float(value)
    except (
        TypeError,
        ValueError,
    ):
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
    except (
        TypeError,
        ValueError,
    ):
        return 0.0

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
    if isinstance(
        value,
        bool,
    ):
        return value

    if isinstance(
        value,
        (int, float),
    ):
        return bool(value)

    if isinstance(
        value,
        str,
    ):
        return value.strip().lower() in {
            "1",
            "true",
            "yes",
            "y",
            "on",
        }

    return False


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

        if (
            text
            and text not in clean_indicators
        ):
            clean_indicators.append(
                text
            )

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
        input_data=str(
            input_data
        ),
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
        action_type = action_mapping.get(
            action
        )

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

        failed_attempts = data.get(
            "failed_attempts",
            0,
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

        analysis_input = {
            "failed_attempts": failed_attempts,
            "new_ip": _bool_value(
                data.get(
                    "new_ip",
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

        incident = _create_incident(
            threat=threat,
            risk=risk,
        )

        login_activity = LoginActivity.objects.create(
            user=request.user,
            ip_address=data.get(
                "ip_address"
            )
            or get_client_ip(request),
            user_agent=data.get(
                "user_agent"
            )
            or request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            device_id=data.get(
                "device_id",
                "",
            ),
            location=data.get(
                "location",
                "",
            ),
            successful=data.get(
                "successful",
                True,
            ),
            failed_attempts=failed_attempts,
            is_new_ip=analysis_input[
                "new_ip"
            ],
            is_new_device=analysis_input[
                "new_device"
            ],
            is_new_location=analysis_input[
                "new_location"
            ],
            unusual_time=analysis_input[
                "unusual_time"
            ],
            impossible_travel=analysis_input[
                "impossible_travel"
            ],
            suspicious_network=analysis_input[
                "suspicious_network"
            ],
        )

        anomaly = Anomaly.objects.create(
            user=request.user,
            anomaly_type="LOGIN",
            risk_score=threat.risk_score,
            severity=threat.severity,
            description=threat.explanation,
            detection_result=result,
        )

        AuditLog.objects.create(
            user=request.user,
            action="LOGIN_ANOMALY_ANALYZED",
            ip_address=get_client_ip(
                request
            ),
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

        response_data = {
            "message": (
                "Login anomaly analysis completed."
            ),
            "login_activity_id": (
                login_activity.id
            ),
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

        behaviour = UserBehaviour.objects.create(
            user=request.user,
            unusual_access=analysis_input[
                "unusual_access"
            ],
            unusual_resource_access=analysis_input[
                "unusual_resource_access"
            ],
            unusual_request_volume=analysis_input[
                "unusual_request_volume"
            ],
            new_device=analysis_input[
                "new_device"
            ],
            new_location=analysis_input[
                "new_location"
            ],
            suspicious_network=analysis_input[
                "suspicious_network"
            ],
            risk_score=threat.risk_score,
            severity=threat.severity,
            analysis_result=result,
        )

        anomaly = Anomaly.objects.create(
            user=request.user,
            anomaly_type="BEHAVIOUR",
            risk_score=threat.risk_score,
            severity=threat.severity,
            description=threat.explanation,
            detection_result=result,
        )

        AuditLog.objects.create(
            user=request.user,
            action="BEHAVIOUR_ANOMALY_ANALYZED",
            ip_address=get_client_ip(
                request
            ),
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


class LoginActivityHistoryView(
    generics.ListAPIView
):
    serializer_class = LoginActivitySerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):
        return LoginActivity.objects.filter(
            user=self.request.user
        ).order_by(
            "-created_at"
        )


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


class BehaviourHistoryView(
    generics.ListAPIView
):
    serializer_class = UserBehaviourSerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):
        return UserBehaviour.objects.filter(
            user=self.request.user
        ).order_by(
            "-created_at"
        )


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


class AnomalyHistoryView(
    generics.ListAPIView
):
    serializer_class = AnomalySerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):
        return Anomaly.objects.filter(
            user=self.request.user
        ).order_by(
            "-detected_at"
        )


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
