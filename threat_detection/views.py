import json
from typing import Any

from django.db import transaction
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.utils import get_client_ip
from audit_logs.models import AuditLog

from ai_engine.anomaly_model import analyze_behavior, analyze_login
from ai_engine.nlp_model import analyze_email, analyze_message
from ai_engine.phishing_model import analyze_url
from ai_engine.risk_engine import analyze_risk

from incidents.models import (
    Incident,
    IncidentEvidence,
    ResponseAction,
)

from .models import Threat, ThreatAnalysis, ThreatEvidence
from .serializers import ThreatSerializer


# ============================================================================
# GENERAL HELPERS
# ============================================================================


def _stringify_input(value: Any) -> str:
    """
    Convert API input into a safe string for Threat.input_data.
    """
    if isinstance(value, str):
        return value

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            default=str,
        )
    except (TypeError, ValueError):
        return str(value)


def _as_dict(value: Any) -> dict:
    """
    Convert input into a dictionary when possible.
    """
    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        try:
            parsed = json.loads(value)

            if isinstance(parsed, dict):
                return parsed

        except (TypeError, ValueError, json.JSONDecodeError):
            pass

    return {}


def _safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    """
    Normalize any score to 0-100.
    """
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


def _normalize_confidence(value: Any) -> float:
    """
    Normalize confidence.

    Supported:
        0.0 - 1.0  -> converted to percentage
        0 - 100    -> kept as percentage
    """
    try:
        confidence = float(value)

    except (TypeError, ValueError):
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


def _unique_indicators(
    model_results: list[tuple[str, dict]],
) -> list[str]:
    """
    Collect unique indicators from all detection engines.
    """
    indicators = []

    for _, result in model_results:

        if not isinstance(result, dict):
            continue

        values = result.get("indicators", [])

        if not isinstance(values, list):
            continue

        for indicator in values:

            if indicator is None:
                continue

            text = str(indicator).strip()

            if not text:
                continue

            if text not in indicators:
                indicators.append(text)

    return indicators


# ============================================================================
# MODEL RESULT PERSISTENCE
# ============================================================================


def _save_model_result(
    threat: Threat,
    model_name: str,
    result: dict,
) -> None:
    """
    Save one detection-engine result into ThreatAnalysis
    and its indicators into ThreatEvidence.
    """

    if not isinstance(result, dict):
        result = {}

    score = _safe_float(
        result.get(
            "risk_score",
            result.get("score", 0),
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

    if not isinstance(indicators, list):
        return

    evidence_objects = []

    for indicator in indicators:

        if indicator is None:
            continue

        indicator_text = str(indicator).strip()

        if not indicator_text:
            continue

        evidence_objects.append(
            ThreatEvidence(
                threat=threat,
                evidence_type=model_name,
                evidence_value=indicator_text,
                risk_contribution=score,
            )
        )

    if evidence_objects:
        ThreatEvidence.objects.bulk_create(
            evidence_objects
        )


# ============================================================================
# DETECTION ENGINE ROUTER
# ============================================================================


def _run_detection_engines(
    threat_type: str,
    source_type: str,
    input_data: Any,
) -> list[tuple[str, dict]]:
    """
    Route incoming data to the existing Guard detection engines.

    Returns:

        [
            ("ENGINE_NAME", result_dict),
            ...
        ]
    """

    results = []

    text_input = _stringify_input(
        input_data
    )

    # ----------------------------------------------------------------------
    # URL
    # ----------------------------------------------------------------------

    if source_type == "URL":

        result = analyze_url(
            text_input
        )

        results.append(
            (
                "URL_PHISHING_ENGINE",
                result,
            )
        )

        return results

    # ----------------------------------------------------------------------
    # EMAIL
    # ----------------------------------------------------------------------

    if source_type == "EMAIL":

        result = analyze_email(
            text_input
        )

        results.append(
            (
                "EMAIL_NLP_ENGINE",
                result,
            )
        )

        return results

    # ----------------------------------------------------------------------
    # MESSAGE
    # ----------------------------------------------------------------------

    if source_type == "MESSAGE":

        result = analyze_message(
            text_input
        )

        results.append(
            (
                "MESSAGE_NLP_ENGINE",
                result,
            )
        )

        return results

    # ----------------------------------------------------------------------
    # LOGIN
    # ----------------------------------------------------------------------

    if source_type == "LOGIN":

        data = _as_dict(
            input_data
        )

        result = analyze_login(
            failed_attempts=data.get(
                "failed_attempts",
                0,
            ),
            new_ip=data.get(
                "new_ip",
                False,
            ),
            new_device=data.get(
                "new_device",
                False,
            ),
            new_location=data.get(
                "new_location",
                False,
            ),
            unusual_time=data.get(
                "unusual_time",
                False,
            ),
            impossible_travel=data.get(
                "impossible_travel",
                False,
            ),
            suspicious_network=data.get(
                "suspicious_network",
                False,
            ),
        )

        results.append(
            (
                "LOGIN_ANOMALY_ENGINE",
                result,
            )
        )

        return results

    # ----------------------------------------------------------------------
    # DEVICE / BEHAVIOUR
    # ----------------------------------------------------------------------

    if source_type == "DEVICE":

        data = _as_dict(
            input_data
        )

        result = analyze_behavior(
            unusual_access=data.get(
                "unusual_access",
                False,
            ),
            unusual_resource_access=data.get(
                "unusual_resource_access",
                False,
            ),
            unusual_request_volume=data.get(
                "unusual_request_volume",
                False,
            ),
            new_device=data.get(
                "new_device",
                False,
            ),
            new_location=data.get(
                "new_location",
                False,
            ),
            suspicious_network=data.get(
                "suspicious_network",
                False,
            ),
        )

        results.append(
            (
                "BEHAVIOUR_ANOMALY_ENGINE",
                result,
            )
        )

        return results

    # ----------------------------------------------------------------------
    # Threat types where NLP can provide useful text analysis
    # ----------------------------------------------------------------------

    if threat_type == "PHISHING":

        result = analyze_message(
            text_input
        )

        results.append(
            (
                "NLP_ENGINE",
                result,
            )
        )

        return results

    if threat_type == "SUSPICIOUS_EMAIL":

        result = analyze_email(
            text_input
        )

        results.append(
            (
                "NLP_ENGINE",
                result,
            )
        )

        return results

    if threat_type == "SUSPICIOUS_MESSAGE":

        result = analyze_message(
            text_input
        )

        results.append(
            (
                "NLP_ENGINE",
                result,
            )
        )

        return results

    # ----------------------------------------------------------------------
    # No dedicated engine yet
    # ----------------------------------------------------------------------

    return results


# ============================================================================
# INCIDENT CREATION
# ============================================================================


def _create_incident(
    threat: Threat,
    recommended_actions: list[str],
) -> Incident | None:
    """
    Automatically create an Incident for HIGH or CRITICAL threats.
    """

    if threat.severity not in {
        "HIGH",
        "CRITICAL",
    }:
        return None

    incident = Incident.objects.create(
        incident_type=threat.threat_type,
        title=(
            f"{threat.severity} "
            f"{threat.threat_type.replace('_', ' ').title()}"
        ),
        description=threat.explanation,
        severity=threat.severity,
        status="OPEN",
        risk_score=threat.risk_score,
        created_by=threat.user,
        source_type=threat.source_type,
        source_id=threat.id,
    )

    # ----------------------------------------------------------------------
    # Copy threat evidence into incident evidence
    # ----------------------------------------------------------------------

    threat_evidence = list(
        threat.evidence.all()
    )

    incident_evidence = []

    for evidence in threat_evidence:

        incident_evidence.append(
            IncidentEvidence(
                incident=incident,
                evidence_type=evidence.evidence_type,
                evidence_value=evidence.evidence_value,
                risk_contribution=evidence.risk_contribution,
            )
        )

    if incident_evidence:
        IncidentEvidence.objects.bulk_create(
            incident_evidence
        )

    # ----------------------------------------------------------------------
    # Recommended action -> ResponseAction
    # ----------------------------------------------------------------------

    action_mapping = {
        "Block suspicious resource": "BLOCK_URL",
        "Quarantine suspicious content": "QUARANTINE_EMAIL",
        "Revoke active sessions": "REVOKE_SESSION",
        "Strengthen authentication": "STRENGTHEN_AUTH",
        "Alert user": "ALERT_USER",
        "Alert administrator": "ALERT_ADMIN",
        "Escalate incident": "ESCALATE",
        "Monitor": "MONITOR",
        "Continue monitoring": "MONITOR",
        "Increase monitoring": "MONITOR",
        "Request additional verification": "STRENGTHEN_AUTH",
        "Alert user if behaviour continues": "ALERT_USER",
    }

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
                "Recommended by automated threat analysis: "
                f"{action}"
            ),
        )

    return incident


# ============================================================================
# THREAT LIST / CREATE
# ============================================================================


class ThreatListCreateView(
    generics.ListCreateAPIView
):
    serializer_class = ThreatSerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):

        return Threat.objects.filter(
            user=self.request.user
        ).order_by(
            "-detected_at"
        )

    def perform_create(
        self,
        serializer,
    ):

        threat = serializer.save(
            user=self.request.user
        )

        AuditLog.objects.create(
            user=self.request.user,
            action="THREAT_CREATED",
            ip_address=get_client_ip(
                self.request
            ),
            user_agent=self.request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"Threat created: "
                f"{threat.threat_type}"
            ),
            status="SUCCESS",
        )


# ============================================================================
# THREAT DETAIL / UPDATE
# ============================================================================


class ThreatDetailView(
    generics.RetrieveUpdateAPIView
):
    serializer_class = ThreatSerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):

        return Threat.objects.filter(
            user=self.request.user
        )

    def perform_update(
        self,
        serializer,
    ):

        threat = serializer.save()

        AuditLog.objects.create(
            user=self.request.user,
            action="THREAT_UPDATED",
            ip_address=get_client_ip(
                self.request
            ),
            user_agent=self.request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"Threat updated: "
                f"{threat.id}"
            ),
            status="SUCCESS",
        )


# ============================================================================
# MAIN AI THREAT ANALYSIS API
# ============================================================================


class ThreatAnalyzeView(
    APIView
):
    permission_classes = [
        IsAuthenticated
    ]

    @transaction.atomic
    def post(
        self,
        request,
    ):
        # ------------------------------------------------------------------
        # 1. Read request
        # ------------------------------------------------------------------

        threat_type = request.data.get(
            "threat_type"
        )

        source_type = request.data.get(
            "source_type"
        )

        input_data = request.data.get(
            "input_data"
        )

        # ------------------------------------------------------------------
        # 2. Required-field validation
        # ------------------------------------------------------------------

        if not threat_type:

            return Response(
                {
                    "detail": (
                        "threat_type is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not source_type:

            return Response(
                {
                    "detail": (
                        "source_type is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if (
            input_data is None
            or input_data == ""
        ):

            return Response(
                {
                    "detail": (
                        "input_data is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ------------------------------------------------------------------
        # 3. Choice validation
        # ------------------------------------------------------------------

        valid_threat_types = dict(
            Threat.THREAT_TYPE_CHOICES
        )

        valid_source_types = dict(
            Threat.SOURCE_TYPE_CHOICES
        )

        if threat_type not in valid_threat_types:

            return Response(
                {
                    "detail": (
                        "Invalid threat_type."
                    ),
                    "allowed_values": list(
                        valid_threat_types.keys()
                    ),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if source_type not in valid_source_types:

            return Response(
                {
                    "detail": (
                        "Invalid source_type."
                    ),
                    "allowed_values": list(
                        valid_source_types.keys()
                    ),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ------------------------------------------------------------------
        # 4. Run detection engines
        # ------------------------------------------------------------------

        model_results = (
            _run_detection_engines(
                threat_type=threat_type,
                source_type=source_type,
                input_data=input_data,
            )
        )

        # ------------------------------------------------------------------
        # 5. Prepare scores for central risk engine
        # ------------------------------------------------------------------

        score_inputs = {}

        for model_name, result in model_results:

            if not isinstance(
                result,
                dict,
            ):
                continue

            score = result.get(
                "risk_score",
                result.get(
                    "score",
                    0,
                ),
            )

            score_inputs[
                model_name
            ] = _safe_float(
                score
            )

        # ------------------------------------------------------------------
        # 6. Central risk calculation
        # ------------------------------------------------------------------

        risk = analyze_risk(
            score_inputs
        )

        risk_score = _safe_float(
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

        if severity not in dict(
            Threat.SEVERITY_CHOICES
        ):
            severity = "SAFE"

        explanation = str(
            risk.get(
                "explanation",
                "",
            )
        )

        recommended_actions = risk.get(
            "recommended_actions",
            [],
        )

        if not isinstance(
            recommended_actions,
            list,
        ):
            recommended_actions = []

        # ------------------------------------------------------------------
        # 7. Add detailed indicators
        # ------------------------------------------------------------------

        indicators = _unique_indicators(
            model_results
        )

        if indicators:

            indicator_text = "; ".join(
                indicators[:10]
            )

            if explanation:
                explanation = (
                    f"{explanation} "
                    f"Key indicators: "
                    f"{indicator_text}"
                )
            else:
                explanation = (
                    "Security indicators detected: "
                    f"{indicator_text}"
                )

        # ------------------------------------------------------------------
        # 8. Create Threat
        # ------------------------------------------------------------------

        threat = Threat.objects.create(
            user=request.user,
            threat_type=threat_type,
            source_type=source_type,
            input_data=_stringify_input(
                input_data
            ),
            risk_score=risk_score,
            severity=severity,
            status="DETECTED",
            explanation=explanation,
        )

        # ------------------------------------------------------------------
        # 9. Save each engine result
        # ------------------------------------------------------------------

        for model_name, result in model_results:

            _save_model_result(
                threat=threat,
                model_name=model_name,
                result=result,
            )

        # ------------------------------------------------------------------
        # 10. No dedicated engine
        # ------------------------------------------------------------------

        if not model_results:

            ThreatAnalysis.objects.create(
                threat=threat,
                model_name="ROUTER",
                model_version="1.0",
                prediction="NO_DEDICATED_ENGINE",
                confidence=0.0,
                score=0.0,
                analysis_result={
                    "message": (
                        "No dedicated detection "
                        "engine is currently mapped "
                        f"for source type "
                        f"{source_type}."
                    ),
                    "threat_type": threat_type,
                    "source_type": source_type,
                },
            )

        # ------------------------------------------------------------------
        # 11. Create incident for HIGH / CRITICAL
        # ------------------------------------------------------------------

        incident = _create_incident(
            threat=threat,
            recommended_actions=recommended_actions,
        )

        # ------------------------------------------------------------------
        # 12. Audit log
        # ------------------------------------------------------------------

        AuditLog.objects.create(
            user=request.user,
            action="THREAT_ANALYZED",
            ip_address=get_client_ip(
                request
            ),
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                "Threat analysis completed. "
                f"Threat ID: {threat.id}; "
                f"score={risk_score}; "
                f"severity={severity}; "
                f"engines={len(model_results)}"
            ),
            status="SUCCESS",
        )

        # ------------------------------------------------------------------
        # 13. Build response
        # ------------------------------------------------------------------

        response_data = {
            "message": (
                "Threat analysis completed."
            ),
            "threat": ThreatSerializer(
                threat
            ).data,
            "analysis": {
                "risk_score": risk_score,
                "severity": severity,
                "explanation": explanation,
                "recommended_actions": (
                    recommended_actions
                ),
                "engines_used": [
                    name
                    for name, _ in model_results
                ],
                "indicator_count": len(
                    indicators
                ),
                "indicators": indicators,
            },
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


# ============================================================================
# THREAT DELETE
# ============================================================================


class ThreatDeleteView(
    generics.DestroyAPIView
):
    serializer_class = ThreatSerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):

        return Threat.objects.filter(
            user=self.request.user
        )

    def perform_destroy(
        self,
        instance,
    ):

        threat_id = instance.id

        instance.delete()

        AuditLog.objects.create(
            user=self.request.user,
            action="THREAT_DELETED",
            ip_address=get_client_ip(
                self.request
            ),
            user_agent=self.request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"Threat deleted. "
                f"Threat ID: {threat_id}"
            ),
            status="SUCCESS",
        )