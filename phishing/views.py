from __future__ import annotations

import json
import os
import re
import shutil
from typing import Any
from urllib.parse import urlparse

from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.files.uploadedfile import UploadedFile
from django.db import transaction

from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from PIL import Image

try:
    import pytesseract
except ImportError:
    pytesseract = None

from accounts.utils import get_client_ip
from audit_logs.models import AuditLog

from ai_engine.trained_classifiers import analyze_phishing_email_ml, analyze_phishing_url_ml
from ai_engine.url_security import analyze_url_security
from ai_engine.risk_engine import analyze_risk
from ai_engine.nlp_model import analyze_email

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
    except (TypeError, ValueError):
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

    return Threat.objects.create(
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
        return (
            PhishingScan.objects
            .filter(
                user=self.request.user
            )
            .order_by(
                "-created_at"
            )
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
        url = request.data.get("url")

        if not isinstance(url, str) or not url.strip():
            return Response(
                {"detail": "url is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        original_url = url.strip()
        candidate_url = original_url if "://" in original_url else f"https://{original_url}"

        try:
            parsed_url = urlparse(candidate_url)
        except ValueError:
            return Response({"detail": "Invalid URL."}, status=status.HTTP_400_BAD_REQUEST)

        if parsed_url.scheme.lower() not in {"http", "https"} or not parsed_url.hostname:
            return Response({"detail": "Invalid URL."}, status=status.HTTP_400_BAD_REQUEST)

        result = analyze_url_security(candidate_url)

        if result.get("is_valid") is False:
            return Response(
                {"detail": result.get("error", "Invalid URL.")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        risk = analyze_risk({"PHISHING_URL_ML_ENGINE": _safe_float(result.get("risk_score", 0))})

        threat = _create_threat(
            user=request.user,
            threat_type="PHISHING" if risk["risk_score"] >= 40 else "MALICIOUS_URL",
            source_type="URL",
            input_data=original_url,
            result=result,
            risk=risk,
        )

        _save_analysis_records(
            threat=threat,
            model_name="PHISHING_URL_ML_ENGINE",
            result=result,
        )

        incident = _create_incident_if_required(threat, risk)

        features = result.get("features", {})
        if not isinstance(features, dict):
            features = {}

        indicators = result.get("indicators", [])
        if not isinstance(indicators, list):
            indicators = []

        google = features.get("google_safe_browsing", {})
        redirect = features.get("redirect_analysis", {})
        trained = features.get("trained_model", {})

        scan = PhishingScan.objects.create(
            user=request.user,
            scan_type="URL",
            input_data=original_url,
            risk_score=threat.risk_score,
            result=threat.severity,
            explanation=threat.explanation,
            status="COMPLETED",
        )

        URLAnalysis.objects.create(
            scan=scan,
            domain=(parsed_url.hostname or "")[:255],
            uses_https=parsed_url.scheme.lower() == "https",
            url_length=len(original_url),
            has_ip_address=bool(trained.get("features", {}).get("ip_address_host", False)),
            has_suspicious_keyword=bool(indicators),
            has_shortener=bool(redirect.get("shortener_detected", False)),
            redirect_count=int(redirect.get("redirect_count", 0) or 0),
            analysis_details=result,
        )

        AuditLog.objects.create(
            user=request.user,
            action="URL_ANALYZED",
            ip_address=get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            description=(
                f"URL analysis completed. Threat ID: {threat.id}; "
                f"score={threat.risk_score}; severity={threat.severity}"
            ),
            status="SUCCESS",
        )

        response_data = {
            "message": "URL analysis completed.",
            "url": original_url,
            "risk_score": threat.risk_score,
            "severity": threat.severity,
            "prediction": result.get("prediction", "UNKNOWN"),
            "confidence": _normalize_confidence(result.get("confidence", 0)),
            "indicators": indicators,
            "features": features,
            "model_results": {
                "trained_url_model": trained,
                "url_security_engine": {
                    "original_url": features.get("original_url", candidate_url),
                    "final_url": features.get("final_url", candidate_url),
                    "original_domain": features.get("original_domain", parsed_url.hostname or ""),
                    "final_domain": features.get("final_domain", ""),
                    "redirect_analysis": redirect,
                    "google_safe_browsing": google,
                    "url_intelligence": features.get("url_intelligence", {}),
                },
            },
            "recommendation": result.get("recommendation", ""),
            "explanation": threat.explanation,
            "recommended_actions": risk.get("recommended_actions", []),
            "threat_id": threat.id,
            "scan_id": scan.id,
        }

        if incident:
            response_data["incident"] = {
                "id": incident.id,
                "severity": incident.severity,
                "status": incident.status,
            }

        return Response(response_data, status=status.HTTP_201_CREATED)


def _extract_email_fields_from_ocr(
    text: str,
) -> dict[str, str]:
    """Extract likely sender/subject/body fields from OCR text."""

    lines = [
        re.sub(r"\\s+", " ", line).strip()
        for line in text.splitlines()
        if line.strip()
    ]

    sender = ""
    subject = ""
    body_lines: list[str] = []

    sender_patterns = [
        re.compile(
            r"^(?:from|sender|mail|email)\\s*[:\\-]\\s*(.+)$",
            re.IGNORECASE,
        ),
        re.compile(
            r"^(.+@[^\\s<>]+)$",
            re.IGNORECASE,
        ),
    ]

    subject_pattern = re.compile(
        r"^(?:subject|sub)\\s*[:\\-]\\s*(.+)$",
        re.IGNORECASE,
    )

    consumed_indexes: set[int] = set()

    for index, line in enumerate(lines):
        subject_match = subject_pattern.match(line)

        if subject_match and not subject:
            subject = subject_match.group(1).strip()
            consumed_indexes.add(index)
            continue

        for pattern in sender_patterns:
            match = pattern.match(line)

            if match:
                candidate = match.group(1).strip().strip("<>")

                try:
                    validate_email(candidate)
                except ValidationError:
                    continue

                if not sender:
                    sender = candidate
                    consumed_indexes.add(index)
                break

    # If the screenshot has no explicit From line, use the first OCR email.
    if not sender:
        email_matches = re.findall(
            r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}",
            text,
            flags=re.IGNORECASE,
        )
        if email_matches:
            sender = email_matches[0].strip()

    # Remove obvious header lines from the body. Preserve the rest of the
    # OCR text exactly enough for the downstream classifier.
    for index, line in enumerate(lines):
        if index in consumed_indexes:
            continue

        if re.match(
            r"^(?:from|sender|mail|email|subject|sub)\\s*[:\\-]",
            line,
            re.IGNORECASE,
        ):
            continue

        body_lines.append(line)

    return {
        "sender": sender,
        "subject": subject,
        "body": "\\n".join(body_lines).strip(),
    }


def _configure_tesseract() -> str | None:
    """Find the Tesseract executable automatically on Windows/Linux."""
    if pytesseract is None:
        return None

    configured = os.getenv("TESSERACT_CMD", "").strip()
    candidates = []

    if configured:
        candidates.append(configured)

    path_executable = shutil.which("tesseract")
    if path_executable:
        candidates.append(path_executable)

    # Common Windows installations. This avoids requiring users to manually
    # add Tesseract to PATH when it is already installed.
    candidates.extend(
        [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Tesseract-OCR\tesseract.exe"),
        ]
    )

    # Common Linux package locations.
    candidates.extend(
        [
            "/usr/bin/tesseract",
            "/usr/local/bin/tesseract",
        ]
    )

    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            pytesseract.pytesseract.tesseract_cmd = candidate
            return candidate

    return None


class EmailScreenshotOCRView(APIView):

    permission_classes = [
        IsAuthenticated
    ]

    def post(
        self,
        request,
    ):
        if pytesseract is None:
            return Response(
                {
                    "detail": (
                        "Python OCR support is not installed. "
                        "Run: pip install pytesseract"
                    )
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        tesseract_path = _configure_tesseract()

        if not tesseract_path:
            return Response(
                {
                    "detail": (
                        "Tesseract OCR engine is not installed or could not "
                        "be found. On Windows run: "
                        "winget install --id UB-Mannheim.TesseractOCR "
                        "-e --accept-source-agreements --accept-package-agreements. "
                        "Then restart the Django server. You can also set "
                        "TESSERACT_CMD to the full tesseract.exe path."
                    ),
                    "ocr_engine": {
                        "installed": False,
                        "python_package": True,
                        "tesseract_path": None,
                    },
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        uploaded: UploadedFile | None = request.FILES.get(
            "screenshot"
        )

        if uploaded is None:
            return Response(
                {
                    "detail": "screenshot image is required."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        allowed_types = {
            "image/png",
            "image/jpeg",
            "image/webp",
            "image/bmp",
        }

        if uploaded.content_type not in allowed_types:
            return Response(
                {
                    "detail": (
                        "Only PNG, JPEG, WEBP and BMP screenshots "
                        "are supported."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        max_size = 10 * 1024 * 1024

        if uploaded.size > max_size:
            return Response(
                {
                    "detail": "Screenshot is too large. Maximum size is 10 MB."
                },
                status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )

        try:
            image = Image.open(uploaded)
            image.verify()
            uploaded.seek(0)
            image = Image.open(uploaded).convert("RGB")

            # OCR the complete screenshot, not only a cropped region.
            raw_text = pytesseract.image_to_string(
                image,
                config="--psm 6",
            ).strip()
        except Exception as exc:
            return Response(
                {
                    "detail": f"Could not read screenshot with OCR: {exc}"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not raw_text:
            return Response(
                {
                    "detail": (
                        "No readable text was detected. Use a clear screenshot "
                        "with the complete email visible."
                    )
                },
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )

        fields = _extract_email_fields_from_ocr(
            raw_text
        )

        email_text = "\n".join(
            part
            for part in [
                f"From: {fields['sender']}" if fields["sender"] else "",
                f"Subject: {fields['subject']}" if fields["subject"] else "",
                fields["body"],
            ]
            if part
        )

        analysis = analyze_email(
            email_text
        )

        return Response(
            {
                "message": "Screenshot OCR completed.",
                "ocr": {
                    "raw_text": raw_text,
                    "text_length": len(raw_text),
                    "engine": "Tesseract OCR",
                },
                "extracted": fields,
                "analysis": analysis,
            },
            status=status.HTTP_200_OK,
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
                        "subject or body is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if sender:
            try:
                validate_email(
                    sender
                )
            except ValidationError:
                return Response(
                    {
                        "detail": (
                            "sender must be a valid "
                            "email address."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        email_payload = {
            "subject": subject,
            "body": body,
            "sender": sender,
        }

        email_text = "\n".join(
            part
            for part in [
                (
                    f"From: {sender}"
                    if sender
                    else ""
                ),
                (
                    f"Subject: {subject}"
                    if subject
                    else ""
                ),
                body,
            ]
            if part
        )

        # Run both engines:
        # 1. trained TF-IDF + Logistic Regression for phishing probability
        # 2. rule/NLP engine for email type, spam, promotional content,
        #    suspicious links and other security indicators.
        ml_result = analyze_phishing_email_ml(email_text) or {}

        if not isinstance(
            ml_result,
            dict,
        ):
            ml_result = {}

        rule_result = analyze_email(email_text) or {}

        if not isinstance(
            rule_result,
            dict,
        ):
            rule_result = {}

        result = dict(rule_result)

        rule_features = result.get(
            "features",
            {},
        )

        if not isinstance(
            rule_features,
            dict,
        ):
            rule_features = {}

        ml_features = ml_result.get(
            "features",
            {},
        )

        if not isinstance(
            ml_features,
            dict,
        ):
            ml_features = {}

        ml_score = _safe_float(
            ml_result.get(
                "risk_score",
                0,
            )
        )

        rule_score = _safe_float(
            result.get(
                "risk_score",
                0,
            )
        )

        # Keep the strongest security signal while retaining both engine
        # outputs for transparency.
        combined_score = max(
            ml_score,
            rule_score,
        )

        result["risk_score"] = combined_score
        result["features"] = {
            **rule_features,
            "trained_model": ml_features,
            "ml_phishing_probability": round(
                ml_score / 100.0,
                4,
            ),
            "ml_prediction": ml_result.get(
                "prediction",
                "UNKNOWN",
            ),
            "ml_confidence": _normalize_confidence(
                ml_result.get(
                    "confidence",
                    0,
                )
            ),
        }
        result["model_results"] = {
            "trained_email_model": ml_result,
            "content_and_security_engine": rule_result,
        }

        # A strong trained phishing result takes priority over content
        # categories such as promotional/spam.
        if ml_score >= 80:
            result["prediction"] = "PHISHING"
        elif ml_score >= 60 and result.get("prediction") not in {
            "PHISHING",
            "LIKELY_PHISHING",
        }:
            result["prediction"] = "LIKELY_PHISHING"

        email_addresses = rule_features.get(
            "email_addresses",
            [],
        )

        sender_valid = bool(sender)
        has_subject = bool(subject)
        has_body = bool(body)

        if sender_valid and (has_subject or has_body):
            email_status = "VALID_EMAIL"
            email_confidence = 95.0
        elif email_addresses and (has_subject or has_body):
            email_status = "POSSIBLE_EMAIL"
            email_confidence = 80.0
        else:
            email_status = "NOT_EMAIL"
            email_confidence = 35.0

        email_validation = {
            "is_email": email_status != "NOT_EMAIL",
            "status": email_status,
            "confidence": email_confidence,
            "sender_valid": sender_valid,
            "subject_present": has_subject,
            "body_present": has_body,
            "email_addresses_found": email_addresses,
            "checks": [
                "Sender address format",
                "Subject/message structure",
                "Email-address patterns in content",
            ],
        }

        result["email_validation"] = email_validation
        result["content_category"] = rule_result.get(
            "content_category",
            "LEGITIMATE",
        )

        raw_score = result.get(
            "risk_score",
            result.get(
                "score",
                0,
            ),
        )

        risk = analyze_risk({"PHISHING_EMAIL_ML_ENGINE": _safe_float(raw_score)})

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
            model_name="PHISHING_EMAIL_ML_ENGINE",
            result=result,
        )

        incident = (
            _create_incident_if_required(
                threat,
                risk,
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

        features = result.get(
            "features",
            {},
        )

        if not isinstance(
            features,
            dict,
        ):
            features = {}

        indicator_text = " ".join(
            str(x)
            for x in indicators
        ).lower()

        urgent = any(
            word in indicator_text
            for word in [
                "urgent",
                "immediately",
                "credential",
                "otp",
            ]
        )

        scan = PhishingScan.objects.create(
            user=request.user,
            scan_type="EMAIL",
            input_data=_stringify_input(
                email_payload
            ),
            risk_score=threat.risk_score,
            result=threat.severity,
            explanation=threat.explanation,
            status="COMPLETED",
        )

        email_analysis = (
            EmailAnalysis.objects.create(
                scan=scan,
                sender=sender,
                subject=subject,
                has_suspicious_keyword=bool(
                    indicators
                ),
                has_urgent_language=urgent,
                has_suspicious_link=(
                    bool(
                        features.get(
                            "urls",
                            [],
                        )
                    )
                    or "http"
                    in body.lower()
                ),
                has_attachment_warning=bool(
                    features.get(
                        "suspicious_attachments",
                        [],
                    )
                ),
                analysis_details={
                    "body": body,
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
                    "indicators": indicators,
                    "features": features,
                    "entities": result.get(
                        "entities",
                        {},
                    ),
                    "recommendation": result.get(
                        "recommendation",
                        "",
                    ),
                    "engine_result": result,
                    "email_validation": email_validation,
                    "content_category": result.get(
                        "content_category",
                        "LEGITIMATE",
                    ),
                    "spam_analysis": {
                        "detected": bool(
                            features.get(
                                "spam_detected",
                                False,
                            )
                        ),
                        "score": features.get(
                            "spam_score",
                            0,
                        ),
                        "keywords": features.get(
                            "spam_keywords",
                            [],
                        ),
                        "reasons": features.get(
                            "spam_reasons",
                            [],
                        ),
                    },
                    "promotional_analysis": {
                        "detected": bool(
                            features.get(
                                "promotional_detected",
                                False,
                            )
                        ),
                        "category": features.get(
                            "promotional_category",
                        ),
                        "keywords": features.get(
                            "promotional_keywords",
                            [],
                        ),
                        "event_keywords": features.get(
                            "event_keywords",
                            [],
                        ),
                        "registration_keywords": features.get(
                            "registration_keywords",
                            [],
                        ),
                        "unsubscribe_detected": bool(
                            features.get(
                                "unsubscribe_detected",
                                False,
                            )
                        ),
                    },
                },
            )
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
            "email_validation": email_validation,
            "content_category": result.get(
                "content_category",
                "LEGITIMATE",
            ),
            "spam_analysis": {
                "detected": bool(
                    features.get(
                        "spam_detected",
                        False,
                    )
                ),
                "score": features.get(
                    "spam_score",
                    0,
                ),
                "keywords": features.get(
                    "spam_keywords",
                    [],
                ),
                "reasons": features.get(
                    "spam_reasons",
                    [],
                ),
            },
            "promotional_analysis": {
                "detected": bool(
                    features.get(
                        "promotional_detected",
                        False,
                    )
                ),
                "category": features.get(
                    "promotional_category",
                ),
                "keywords": features.get(
                    "promotional_keywords",
                    [],
                ),
                "event_keywords": features.get(
                    "event_keywords",
                    [],
                ),
                "registration_keywords": features.get(
                    "registration_keywords",
                    [],
                ),
                "unsubscribe_detected": bool(
                    features.get(
                        "unsubscribe_detected",
                        False,
                    )
                ),
            },
            "model_results": result.get(
                "model_results",
                {},
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
        return (
            PhishingScan.objects
            .filter(
                user=self.request.user
            )
            .order_by(
                "-created_at"
            )
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