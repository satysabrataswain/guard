import os
import tempfile

from django.core.files.uploadedfile import UploadedFile

from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import (
    ImpersonationScan,
    DeepfakeAnalysis,
    IdentityAnalysis,
    ImpersonationEvidence,
)

from .serializers import (
    ImpersonationScanSerializer,
)

from audit_logs.models import AuditLog
from accounts.utils import get_client_ip

from ai_engine.image_model import (
    analyze_image_file,
    analyze_video_file,
)


MAX_FILE_SIZE = 20 * 1024 * 1024

IMAGE_EXTENSIONS = [
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
]

VIDEO_EXTENSIONS = [
    ".mp4",
    ".mov",
    ".avi",
    ".mkv",
    ".webm",
]


def validate_uploaded_file(
    uploaded_file,
    allowed_extensions,
):

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
    uploaded_file,
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
            .order_by("-created_at")
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
                    "detail":
                    "image file is required."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        validation_error = (
            validate_uploaded_file(
                uploaded_file,
                IMAGE_EXTENSIONS,
            )
        )

        if validation_error:

            return Response(
                {
                    "detail":
                    validation_error
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        temp_path = None

        try:

            temp_path = (
                save_uploaded_temp_file(
                    uploaded_file
                )
            )

            ai_result = (
                analyze_image_file(
                    temp_path,
                    uploaded_file.name,
                    uploaded_file.size,
                )
            )

        except Exception as error:

            return Response(
                {
                    "detail":
                    "AI image analysis failed.",
                    "error":
                    str(error),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        finally:

            if (
                temp_path
                and os.path.exists(temp_path)
            ):
                os.remove(temp_path)

        if not ai_result.get(
            "is_valid",
            False,
        ):

            return Response(
                {
                    "detail":
                    ai_result.get(
                        "error",
                        "Image analysis failed.",
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        score = ai_result.get(
            "risk_score",
            0,
        )

        severity = ai_result.get(
            "severity",
            "SAFE",
        )

        explanation = (
            f"Advanced AI deepfake image analysis "
            f"completed. Ensemble risk score: "
            f"{score}/100. "
            f"Classification: {severity}. "
            f"{ai_result.get('recommendation', '')}"
        )

        scan = (
            ImpersonationScan.objects.create(
                user=request.user,
                scan_type="IMAGE",
                file_name=uploaded_file.name,
                file_size=uploaded_file.size,
                risk_score=score,
                result=severity,
                explanation=explanation,
                status="COMPLETED",
            )
        )

        features = ai_result.get(
            "features",
            {},
        )

        DeepfakeAnalysis.objects.create(
            scan=scan,
            face_detected=features.get(
                "face_detected",
                False,
            ),
            multiple_faces=features.get(
                "face_count",
                0,
            ) > 1,
            face_manipulation_indicator=(
                score >= 60
            ),
            lighting_inconsistency=False,
            edge_artifact_indicator=False,
            compression_anomaly=False,
            metadata_missing=False,
            analysis_details=ai_result,
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
                ai_result.get(
                    "indicators",
                    [],
                )
            ),
            analysis_details={
                "ai_prediction":
                ai_result.get(
                    "prediction"
                ),
                "confidence":
                ai_result.get(
                    "confidence"
                ),
                "models":
                features.get(
                    "models_used",
                    [],
                ),
            },
        )

        indicators = ai_result.get(
            "indicators",
            [],
        )

        if not indicators:
            indicators = [
                "No major AI manipulation indicator detected."
            ]

        for item in indicators:

            ImpersonationEvidence.objects.create(
                scan=scan,
                evidence_type="AI_DEEPFAKE",
                evidence_value=item,
                risk_contribution=score,
            )

        AuditLog.objects.create(
            user=request.user,
            action="IMPERSONATION_DETECTED",
            ip_address=get_client_ip(
                request
            ),
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"Advanced AI image deepfake "
                f"analysis performed. "
                f"Scan ID: {scan.id}"
            ),
            status="SUCCESS",
        )

        return Response(
            {
                "message":
                "Advanced AI image analysis completed.",

                "ai_analysis":
                ai_result,

                "scan":
                ImpersonationScanSerializer(
                    scan
                ).data,
            },
            status=status.HTTP_201_CREATED,
        )


class VideoAnalyzeView(APIView):

    permission_classes = [
        IsAuthenticated
    ]

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
                    "detail":
                    "video file is required."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        validation_error = (
            validate_uploaded_file(
                uploaded_file,
                VIDEO_EXTENSIONS,
            )
        )

        if validation_error:

            return Response(
                {
                    "detail":
                    validation_error
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        temp_path = None

        try:

            temp_path = (
                save_uploaded_temp_file(
                    uploaded_file
                )
            )

            ai_result = (
                analyze_video_file(
                    temp_path,
                    uploaded_file.name,
                    uploaded_file.size,
                    max_frames=16,
                )
            )

        except Exception as error:

            return Response(
                {
                    "detail":
                    "AI video analysis failed.",
                    "error":
                    str(error),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        finally:

            if (
                temp_path
                and os.path.exists(temp_path)
            ):
                os.remove(temp_path)

        if not ai_result.get(
            "is_valid",
            False,
        ):

            return Response(
                {
                    "detail":
                    ai_result.get(
                        "error",
                        "Video analysis failed.",
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        score = ai_result.get(
            "risk_score",
            0,
        )

        severity = ai_result.get(
            "severity",
            "SAFE",
        )

        explanation = (
            f"Advanced AI deepfake video analysis "
            f"completed. Ensemble risk score: "
            f"{score}/100. Classification: "
            f"{severity}. "
            f"{ai_result.get('recommendation', '')}"
        )

        scan = (
            ImpersonationScan.objects.create(
                user=request.user,
                scan_type="VIDEO",
                file_name=uploaded_file.name,
                file_size=uploaded_file.size,
                risk_score=score,
                result=severity,
                explanation=explanation,
                status="COMPLETED",
            )
        )

        features = ai_result.get(
            "features",
            {},
        )

        DeepfakeAnalysis.objects.create(
            scan=scan,
            face_detected=features.get(
                "face_detected",
                False,
            ),
            multiple_faces=features.get(
                "multiple_faces",
                False,
            ),
            face_manipulation_indicator=(
                score >= 60
            ),
            lighting_inconsistency=False,
            edge_artifact_indicator=False,
            compression_anomaly=False,
            metadata_missing=False,
            analysis_details=ai_result,
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
                ai_result.get(
                    "indicators",
                    [],
                )
            ),
            analysis_details={
                "ai_prediction":
                ai_result.get(
                    "prediction"
                ),
                "confidence":
                ai_result.get(
                    "confidence"
                ),
                "models":
                features.get(
                    "models_used",
                    [],
                ),
            },
        )

        indicators = ai_result.get(
            "indicators",
            [],
        )

        if not indicators:
            indicators = [
                "No major AI manipulation indicator detected."
            ]

        for item in indicators:

            ImpersonationEvidence.objects.create(
                scan=scan,
                evidence_type="AI_VIDEO",
                evidence_value=item,
                risk_contribution=score,
            )

        AuditLog.objects.create(
            user=request.user,
            action="DEEPFAKE_DETECTED",
            ip_address=get_client_ip(
                request
            ),
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"Advanced AI video deepfake "
                f"analysis performed. "
                f"Scan ID: {scan.id}"
            ),
            status="SUCCESS",
        )

        return Response(
            {
                "message":
                "Advanced AI video analysis completed.",

                "ai_analysis":
                ai_result,

                "scan":
                ImpersonationScanSerializer(
                    scan
                ).data,
            },
            status=status.HTTP_201_CREATED,
        )


class ImpersonationDeleteView(
    generics.DestroyAPIView
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