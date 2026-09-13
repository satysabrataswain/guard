from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from django.core.files.uploadedfile import UploadedFile
from django.db import transaction
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.utils import get_client_ip
from audit_logs.models import AuditLog

from ai_engine.image_model import (
    analyze_image_file,
    analyze_video_file,
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
    DeepfakeAnalysis,
    IdentityAnalysis,
    ImpersonationEvidence,
    ImpersonationScan,
)

from .serializers import (
    ImpersonationScanSerializer,
)


MAX_FILE_SIZE = 20 * 1024 * 1024

IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
}

VIDEO_EXTENSIONS = {
    ".mp4",
    ".mov",
    ".avi",
    ".mkv",
    ".webm",
}


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


def _stringify(
    value: Any,
) -> str:
    if isinstance(
        value,
        str,
    ):
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


def validate_uploaded_file(
    uploaded_file: UploadedFile,
    allowed_extensions: set[str],
) -> str | None:

    if not isinstance(
        uploaded_file,
        UploadedFile,
    ):
        return "Invalid uploaded file."

    if uploaded_file.size <= 0:
        return "Uploaded file is empty."

    if uploaded_file.size > MAX_FILE_SIZE:
        return "File size exceeds the 20 MB limit."

    extension = os.path.splitext(
        uploaded_file.name
    )[1].lower()

    if extension not in allowed_extensions:
        return "Unsupported file type."

    return None


def save_uploaded_temp_file(
    uploaded_file: UploadedFile,
) -> str:

    suffix = os.path.splitext(
        uploaded_file.name
    )[1].lower()

    temp_file = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=suffix,
    )

    try:
        for chunk in uploaded_file.chunks():
            temp_file.write(chunk)

        temp_file.flush()

    finally:
        temp_file.close()

    return temp_file.name


def _build_explanation(
    ai_result: dict,
    risk: dict,
) -> str:

    score = _safe_float(
        risk.get(
            "risk_score",
            ai_result.get(
                "risk_score",
                0,
            ),
        )
    )

    severity = str(
        risk.get(
            "severity",
            ai_result.get(
                "severity",
                "SAFE",
            ),
        )
    ).upper()

    prediction = str(
        ai_result.get(
            "prediction",
            "UNKNOWN",
        )
    )

    recommendation = str(
        ai_result.get(
            "recommendation",
            "",
        )
    )

    indicators = ai_result.get(
        "indicators",
        [],
    )

    if not isinstance(
        indicators,
        list,
    ):
        indicators = []

    parts = [
        "AI media analysis completed.",
        f"Risk score: {score}/100.",
        f"Classification: {severity}.",
        f"Prediction: {prediction}.",
    ]

    if indicators:
        parts.append(
            "Key indicators: "
            + "; ".join(
                str(item)
                for item in indicators[:8]
                if item
            )
        )

    if recommendation:
        parts.append(
            f"Recommendation: {recommendation}"
        )

    return " ".join(parts)


def _create_threat(
    user,
    scan_type: str,
    file_name: str,
    file_size: int,
    ai_result: dict,
    risk: dict,
) -> Threat:

    threat_type = "DEEPFAKE"

    source_type = (
        "IMAGE"
        if scan_type == "IMAGE"
        else "VIDEO"
    )

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

    explanation = _build_explanation(
        ai_result,
        risk,
    )

    input_data = {
        "file_name": file_name,
        "file_size": file_size,
        "scan_type": scan_type,
        "prediction": ai_result.get(
            "prediction",
            "UNKNOWN",
        ),
        "confidence": ai_result.get(
            "confidence",
            0,
        ),
        "features": ai_result.get(
            "features",
            {},
        ),
    }

    return Threat.objects.create(
        user=user,
        threat_type=threat_type,
        source_type=source_type,
        input_data=_stringify(
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
    ai_result: dict,
) -> None:

    score = _safe_float(
        ai_result.get(
            "risk_score",
            0,
        )
    )

    confidence = _normalize_confidence(
        ai_result.get(
            "confidence",
            0,
        )
    )

    prediction = str(
        ai_result.get(
            "prediction",
            "UNKNOWN",
        )
    )[:100]

    ThreatAnalysis.objects.create(
        threat=threat,
        model_name=model_name,
        model_version="1.0-deepfake-ensemble",
        prediction=prediction,
        confidence=confidence,
        score=score,
        analysis_result=ai_result,
    )

    indicators = ai_result.get(
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

        value = str(
            indicator
        ).strip()

        if not value:
            continue

        evidence_objects.append(
            ThreatEvidence(
                threat=threat,
                evidence_type=model_name,
                evidence_value=value,
                risk_contribution=score,
            )
        )

    if evidence_objects:
        ThreatEvidence.objects.bulk_create(
            evidence_objects
        )


def _save_impersonation_records(
    scan: ImpersonationScan,
    ai_result: dict,
) -> None:

    features = ai_result.get(
        "features",
        {},
    )

    if not isinstance(
        features,
        dict,
    ):
        features = {}

    score = _safe_float(
        ai_result.get(
            "risk_score",
            0,
        )
    )

    scan_type = scan.scan_type

    DeepfakeAnalysis.objects.create(
        scan=scan,
        face_detected=bool(
            features.get(
                "face_detected",
                False,
            )
        ),
        multiple_faces=bool(
            features.get(
                "multiple_faces",
                features.get(
                    "face_count",
                    0,
                ) > 1,
            )
        ),
        face_manipulation_indicator=(
            score >= 60
        ),
        lighting_inconsistency=bool(
            features.get(
                "lighting_inconsistency",
                False,
            )
        ),
        edge_artifact_indicator=bool(
            features.get(
                "edge_artifact_indicator",
                False,
            )
        ),
        compression_anomaly=bool(
            features.get(
                "compression_anomaly",
                False,
            )
        ),
        metadata_missing=bool(
            features.get(
                "metadata_missing",
                False,
            )
        ),
        analysis_details=ai_result,
    )

    indicators = ai_result.get(
        "indicators",
        [],
    )

    if not isinstance(
        indicators,
        list,
    ):
        indicators = []

    identity_indicators = list(
        dict.fromkeys(
            str(item).strip()
            for item in indicators
            if item
        )
    )

    IdentityAnalysis.objects.create(
        scan=scan,
        identity_match_indicator=False,
        face_swap_indicator=(
            score >= 80
        ),
        suspicious_face_region=(
            score >= 60
        ),
        visual_mismatch_indicator=(
            score >= 60
        ),
        impersonation_indicators=(
            identity_indicators
        ),
        analysis_details={
            "scan_type": scan_type,
            "prediction": ai_result.get(
                "prediction",
                "UNKNOWN",
            ),
            "confidence": ai_result.get(
                "confidence",
                0,
            ),
            "features": features,
        },
    )

    if not identity_indicators:
        identity_indicators = [
            "No major AI manipulation indicator detected."
        ]

    evidence_type = (
        "AI_IMAGE"
        if scan_type == "IMAGE"
        else "AI_VIDEO"
    )

    for indicator in identity_indicators:

        ImpersonationEvidence.objects.create(
            scan=scan,
            evidence_type=evidence_type,
            evidence_value=indicator,
            risk_contribution=score,
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
        incident_type="DEEPFAKE",
        title=(
            f"{threat.severity} "
            "Digital Impersonation / Deepfake"
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
        "Quarantine suspicious content": (
            "QUARANTINE_EMAIL"
        ),
        "Revoke active sessions": (
            "REVOKE_SESSION"
        ),
        "Strengthen authentication": (
            "STRENGTHEN_AUTH"
        ),
        "Alert user": "ALERT_USER",
        "Alert administrator": "ALERT_ADMIN",
        "Escalate incident": "ESCALATE",
        "Monitor": "MONITOR",
        "Continue monitoring": "MONITOR",
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
                f"deepfake analysis: {action}"
            ),
        )

    return incident


def _run_media_analysis(
    uploaded_file: UploadedFile,
    scan_type: str,
) -> dict:

    temp_path = None

    try:

        temp_path = (
            save_uploaded_temp_file(
                uploaded_file
            )
        )

        if scan_type == "IMAGE":

            return analyze_image_file(
                temp_path,
                uploaded_file.name,
                uploaded_file.size,
            )

        return analyze_video_file(
            temp_path,
            uploaded_file.name,
            uploaded_file.size,
            max_frames=16,
        )

    finally:

        if (
            temp_path
            and os.path.exists(temp_path)
        ):
            try:
                os.remove(temp_path)
            except OSError:
                pass


def _analyze_uploaded_media(
    request,
    uploaded_file: UploadedFile,
    scan_type: str,
):
    allowed_extensions = (
        IMAGE_EXTENSIONS
        if scan_type == "IMAGE"
        else VIDEO_EXTENSIONS
    )

    validation_error = (
        validate_uploaded_file(
            uploaded_file,
            allowed_extensions,
        )
    )

    if validation_error:

        return Response(
            {
                "detail": validation_error,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:

        ai_result = _run_media_analysis(
            uploaded_file,
            scan_type,
        )

    except Exception as error:

        AuditLog.objects.create(
            user=request.user,
            action="MEDIA_ANALYSIS_FAILED",
            ip_address=get_client_ip(
                request
            ),
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"{scan_type} AI analysis failed: "
                f"{str(error)}"
            ),
            status="FAILED",
        )

        return Response(
            {
                "detail": (
                    f"AI {scan_type.lower()} "
                    "analysis failed."
                ),
                "error": str(error),
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    if not isinstance(
        ai_result,
        dict,
    ):
        ai_result = {}

    if not ai_result.get(
        "is_valid",
        False,
    ):

        return Response(
            {
                "detail": ai_result.get(
                    "error",
                    "Media analysis failed.",
                )
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    model_score = _safe_float(
        ai_result.get(
            "risk_score",
            0,
        )
    )

    model_name = (
        "DEEPFAKE_IMAGE_ENGINE"
        if scan_type == "IMAGE"
        else "DEEPFAKE_VIDEO_ENGINE"
    )

    risk = analyze_risk(
        {
            model_name: model_score,
        }
    )

    with transaction.atomic():

        scan = ImpersonationScan.objects.create(
            user=request.user,
            scan_type=scan_type,
            file_name=uploaded_file.name,
            file_size=uploaded_file.size,
            risk_score=_safe_float(
                risk.get(
                    "risk_score",
                    model_score,
                )
            ),
            result=str(
                risk.get(
                    "severity",
                    "SAFE",
                )
            ).upper(),
            explanation=_build_explanation(
                ai_result,
                risk,
            ),
            status="COMPLETED",
        )

        threat = _create_threat(
            user=request.user,
            scan_type=scan_type,
            file_name=uploaded_file.name,
            file_size=uploaded_file.size,
            ai_result=ai_result,
            risk=risk,
        )

        _save_threat_analysis(
            threat=threat,
            model_name=model_name,
            ai_result=ai_result,
        )

        _save_impersonation_records(
            scan=scan,
            ai_result=ai_result,
        )

        incident = (
            _create_incident_if_required(
                threat,
                risk,
            )
        )

        AuditLog.objects.create(
            user=request.user,
            action=(
                "IMAGE_DEEPFAKE_ANALYZED"
                if scan_type == "IMAGE"
                else "VIDEO_DEEPFAKE_ANALYZED"
            ),
            ip_address=get_client_ip(
                request
            ),
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"{scan_type} deepfake analysis "
                f"completed. "
                f"Scan ID: {scan.id}; "
                f"Threat ID: {threat.id}; "
                f"score={threat.risk_score}; "
                f"severity={threat.severity}"
            ),
            status="SUCCESS",
        )

    response_data = {
        "message": (
            f"AI {scan_type.lower()} analysis "
            "completed."
        ),
        "ai_analysis": ai_result,
        "risk": risk,
        "threat_id": threat.id,
        "scan": ImpersonationScanSerializer(
            scan
        ).data,
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


class ImpersonationHistoryView(
    generics.ListAPIView
):
    serializer_class = (
        ImpersonationScanSerializer
    )

    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):

        return (
            ImpersonationScan.objects
            .filter(
                user=self.request.user
            )
            .order_by(
                "-created_at"
            )
        )


class ImpersonationDetailView(
    generics.RetrieveAPIView
):
    serializer_class = (
        ImpersonationScanSerializer
    )

    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):

        return (
            ImpersonationScan.objects
            .filter(
                user=self.request.user
            )
        )


class ImageAnalyzeView(APIView):
    permission_classes = [
        IsAuthenticated
    ]

    @transaction.atomic
    def post(
        self,
        request,
    ):

        uploaded_file = request.FILES.get(
            "image"
        )

        if not uploaded_file:

            return Response(
                {
                    "detail": (
                        "image file is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        return _analyze_uploaded_media(
            request=request,
            uploaded_file=uploaded_file,
            scan_type="IMAGE",
        )


class VideoAnalyzeView(APIView):
    permission_classes = [
        IsAuthenticated
    ]

    @transaction.atomic
    def post(
        self,
        request,
    ):

        uploaded_file = request.FILES.get(
            "video"
        )

        if not uploaded_file:

            return Response(
                {
                    "detail": (
                        "video file is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        return _analyze_uploaded_media(
            request=request,
            uploaded_file=uploaded_file,
            scan_type="VIDEO",
        )
