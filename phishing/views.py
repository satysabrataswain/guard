import json
from typing import Any

from django.db import transaction
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.utils import get_client_ip
from audit_logs.models import AuditLog

from ai_engine.nlp_model import analyze_email
from ai_engine.phishing_model import analyze_url
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
    EmailAnalysis,
    PhishingScan,
    URLAnalysis,
)

from .serializers import (
    EmailAnalysisSerializer,
    PhishingScanSerializer,
    URLAnalysisSerializer,
)


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


def _stringify_input(
    value: Any,
) -> str:
    if isinstance(value, str):
        return value

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            default=str,
        )
    except (
        TypeError,
        ValueError,
    ):
        return str(value)


def _create_threat(
    user,
    threat_type: str,
    source_type: str,
    input_data: Any,
    result: dict,
    risk: dict,
) -> Threat:
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

    valid_severities = dict(
        Threat.SEVERITY_CHOICES
    )

    if severity not in valid_severities:
        severity = "SAFE"

    explanation = str(
        risk.get(
            "explanation",
            "",
        )
    )

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
                "Security indicators detected: "
                f"{indicator_text}"
            )

    threat = Threat.objects.create(
        user=user,
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

    return threat


def _save_analysis_records(
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

    evidence = []

    for indicator in indicators:
        if indicator is None:
            continue

        value = str(
            indicator
        ).strip()

        if not value:
            continue

        evidence.append(
            ThreatEvidence(
                threat=threat,
                evidence_type=model_name,
                evidence_value=value,
                risk_contribution=score,
            )
        )

    if evidence:
        ThreatEvidence.objects.bulk_create(
            evidence
        )


def _create_incident_if_required(
    threat: Threat,
    risk: dict,
) -> Incident | None:
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

    for evidence in threat.evidence.all():
        IncidentEvidence.objects.create(
            incident=incident,
            evidence_type=evidence.evidence_type,
            evidence_value=evidence.evidence_value,
            risk_contribution=evidence.risk_contribution,
        )

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
                f"security analysis: {action}"
            ),
        )

    return incident


class PhishingScanListCreateView(
    generics.ListCreateAPIView
):
    serializer_class = PhishingScanSerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):
        return PhishingScan.objects.filter(
            user=self.request.user
        ).order_by(
            "-created_at"
        )

    def perform_create(
        self,
        serializer,
    ):
        scan = serializer.save(
            user=self.request.user
        )

        AuditLog.objects.create(
            user=self.request.user,
            action="PHISHING_SCAN_CREATED",
            ip_address=get_client_ip(
                self.request
            ),
            user_agent=self.request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"Phishing scan created: "
                f"{scan.id}"
            ),
            status="SUCCESS",
        )


class PhishingScanDetailView(
    generics.RetrieveUpdateAPIView
):
    serializer_class = PhishingScanSerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):
        return PhishingScan.objects.filter(
            user=self.request.user
        )

    def perform_update(
        self,
        serializer,
    ):
        scan = serializer.save()

        AuditLog.objects.create(
            user=self.request.user,
            action="PHISHING_SCAN_UPDATED",
            ip_address=get_client_ip(
                self.request
            ),
            user_agent=self.request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"Phishing scan updated: "
                f"{scan.id}"
            ),
            status="SUCCESS",
        )


class PhishingScanDeleteView(
    generics.DestroyAPIView
):
    serializer_class = PhishingScanSerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):
        return PhishingScan.objects.filter(
            user=self.request.user
        )

    def perform_destroy(
        self,
        instance,
    ):
        scan_id = instance.id

        instance.delete()

        AuditLog.objects.create(
            user=self.request.user,
            action="PHISHING_SCAN_DELETED",
            ip_address=get_client_ip(
                self.request
            ),
            user_agent=self.request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"Phishing scan deleted: "
                f"{scan_id}"
            ),
            status="SUCCESS",
        )


class URLAnalysisView(APIView):
    permission_classes = [
        IsAuthenticated
    ]

    @transaction.atomic
    def post(
        self,
        request,
    ):
        url = request.data.get(
            "url"
        )

        if not url:
            return Response(
                {
                    "detail": (
                        "url is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not isinstance(
            url,
            str,
        ):
            return Response(
                {
                    "detail": (
                        "url must be a string."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        url = url.strip()

        if not url:
            return Response(
                {
                    "detail": (
                        "url cannot be empty."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        result = analyze_url(
            url
        )

        if not isinstance(
            result,
            dict,
        ):
            result = {}

        raw_score = result.get(
            "risk_score",
            result.get(
                "score",
                0,
            ),
        )

        risk = analyze_risk(
            {
                "URL_PHISHING_ENGINE":
                    _safe_float(
                        raw_score
                    )
            }
        )

        threat = _create_threat(
            user=request.user,
            threat_type="PHISHING"
            if risk["risk_score"] >= 40
            else "MALICIOUS_URL",
            source_type="URL",
            input_data=url,
            result=result,
            risk=risk,
        )

        _save_analysis_records(
            threat=threat,
            model_name="URL_PHISHING_ENGINE",
            result=result,
        )

        incident = (
            _create_incident_if_required(
                threat,
                risk,
            )
        )

        scan = PhishingScan.objects.create(
            user=request.user,
            scan_type="URL",
            target=url,
            risk_score=threat.risk_score,
            severity=threat.severity,
            result=result,
        )

        URLAnalysis.objects.create(
            scan=scan,
            url=url,
            risk_score=threat.risk_score,
            prediction=str(
                result.get(
                    "prediction",
                    "UNKNOWN",
                )
            ),
            confidence=_normalize_confidence(
                result.get(
                    "confidence",
                    0,
                )
            ),
            indicators=result.get(
                "indicators",
                [],
            ),
            features=result.get(
                "features",
                {},
            ),
            recommendation=result.get(
                "recommendation",
                "",
            ),
        )

        AuditLog.objects.create(
            user=request.user,
            action="URL_ANALYZED",
            ip_address=get_client_ip(
                request
            ),
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"URL analysis completed. "
                f"Threat ID: {threat.id}; "
                f"score={threat.risk_score}; "
                f"severity={threat.severity}"
            ),
            status="SUCCESS",
        )

        response_data = {
            "message": (
                "URL analysis completed."
            ),
            "url": url,
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
            "features": result.get(
                "features",
                {},
            ),
            "recommendation": result.get(
                "recommendation",
                "",
            ),
            "explanation": threat.explanation,
            "recommended_actions": risk.get(
                "recommended_actions",
                [],
            ),
            "threat_id": threat.id,
            "scan_id": scan.id,
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


class EmailAnalysisView(APIView):
    permission_classes = [
        IsAuthenticated
    ]

    @transaction.atomic
    def post(
        self,
        request,
    ):
        subject = str(
            request.data.get(
                "subject",
                "",
            )
        ).strip()

        body = str(
            request.data.get(
                "body",
                "",
            )
        ).strip()

        sender = str(
            request.data.get(
                "sender",
                "",
            )
        ).strip()

        if not subject and not body:
            return Response(
                {
                    "detail": (
                        "subject or body "
                        "is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        email_payload = {
            "subject": subject,
            "body": body,
            "sender": sender,
        }

        result = analyze_email(
            email_payload
        )

        if not isinstance(
            result,
            dict,
        ):
            result = {}

        raw_score = result.get(
            "risk_score",
            result.get(
                "score",
                0,
            ),
        )

        risk = analyze_risk(
            {
                "EMAIL_NLP_ENGINE":
                    _safe_float(
                        raw_score
                    )
            }
        )

        threat = _create_threat(
            user=request.user,
            threat_type="SUSPICIOUS_EMAIL",
            source_type="EMAIL",
            input_data=email_payload,
            result=result,
            risk=risk,
        )

        _save_analysis_records(
            threat=threat,
            model_name="EMAIL_NLP_ENGINE",
            result=result,
        )

        incident = (
            _create_incident_if_required(
                threat,
                risk,
            )
        )

        scan = PhishingScan.objects.create(
            user=request.user,
            scan_type="EMAIL",
            target=sender or "EMAIL_CONTENT",
            risk_score=threat.risk_score,
            severity=threat.severity,
            result=result,
        )

        email_analysis = EmailAnalysis.objects.create(
            scan=scan,
            sender=sender,
            subject=subject,
            body=body,
            risk_score=threat.risk_score,
            prediction=str(
                result.get(
                    "prediction",
                    "UNKNOWN",
                )
            ),
            confidence=_normalize_confidence(
                result.get(
                    "confidence",
                    0,
                )
            ),
            indicators=result.get(
                "indicators",
                [],
            ),
            entities=result.get(
                "entities",
                {},
            ),
            recommendation=result.get(
                "recommendation",
                "",
            ),
        )

        AuditLog.objects.create(
            user=request.user,
            action="EMAIL_ANALYZED",
            ip_address=get_client_ip(
                request
            ),
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"Email analysis completed. "
                f"Threat ID: {threat.id}; "
                f"score={threat.risk_score}; "
                f"severity={threat.severity}"
            ),
            status="SUCCESS",
        )

        response_data = {
            "message": (
                "Email analysis completed."
            ),
            "email_analysis_id": (
                email_analysis.id
            ),
            "scan_id": scan.id,
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
            "entities": result.get(
                "entities",
                {},
            ),
            "recommendation": result.get(
                "recommendation",
                "",
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


class PhishingHistoryView(
    generics.ListAPIView
):
    serializer_class = PhishingScanSerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):
        return PhishingScan.objects.filter(
            user=self.request.user
        ).order_by(
            "-created_at"
        )


class PhishingDetailView(
    generics.RetrieveAPIView
):
    serializer_class = PhishingScanSerializer
    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):
        return PhishingScan.objects.filter(
            user=self.request.user
        )
