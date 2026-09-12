import os

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


def get_severity(score):

    if score <= 19:
        return "SAFE"

    if score <= 39:
        return "LOW"

    if score <= 59:
        return "MEDIUM"

    if score <= 79:
        return "HIGH"

    return "CRITICAL"


def validate_uploaded_file(
    uploaded_file,
    allowed_extensions,
):

    if not isinstance(
        uploaded_file,
        UploadedFile
    ):
        return "Invalid uploaded file."

    if uploaded_file.size <= 0:
        return "Uploaded file is empty."

    if uploaded_file.size > MAX_FILE_SIZE:
        return (
            "File size exceeds the 20 MB limit."
        )

    extension = os.path.splitext(
        uploaded_file.name
    )[1].lower()

    if extension not in allowed_extensions:
        return (
            "Unsupported file type."
        )

    return None


class ImpersonationHistoryView(
    generics.ListAPIView
):

    serializer_class = ImpersonationScanSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):

        return ImpersonationScan.objects.filter(
            user=self.request.user
        ).order_by("-created_at")


class ImpersonationDetailView(
    generics.RetrieveAPIView
):

    serializer_class = ImpersonationScanSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):

        return ImpersonationScan.objects.filter(
            user=self.request.user
        )


class ImageAnalyzeView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

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

        validation_error = validate_uploaded_file(
            uploaded_file,
            IMAGE_EXTENSIONS,
        )

        if validation_error:

            return Response(
                {
                    "detail":
                    validation_error
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        score = 0

        evidence = []

        file_name = uploaded_file.name

        file_size = uploaded_file.size

        extension = os.path.splitext(
            file_name
        )[1].lower()

        # --------------------------------
        # Initial forensic indicators
        # --------------------------------

        metadata_missing = True

        score += 5

        evidence.append(
            "Image metadata is not available "
            "for the initial analysis."
        )

        # --------------------------------
        # Important:
        # Missing metadata is NOT proof
        # of manipulation.
        # --------------------------------

        explanation = (
            "Initial image impersonation analysis "
            "completed. No full deepfake model is "
            "connected yet. Metadata availability "
            "is treated only as supporting evidence."
        )

        result = get_severity(score)

        scan = ImpersonationScan.objects.create(
            user=request.user,
            scan_type="IMAGE",
            file_name=file_name,
            file_size=file_size,
            risk_score=score,
            result=result,
            explanation=explanation,
            status="COMPLETED",
        )

        DeepfakeAnalysis.objects.create(
            scan=scan,
            face_detected=False,
            multiple_faces=False,
            face_manipulation_indicator=False,
            lighting_inconsistency=False,
            edge_artifact_indicator=False,
            compression_anomaly=False,
            metadata_missing=metadata_missing,
            analysis_details={
                "file_extension": extension,
                "evidence": evidence,
                "note": (
                    "Computer vision/deepfake model "
                    "will be connected later."
                ),
            },
        )

        IdentityAnalysis.objects.create(
            scan=scan,
            identity_match_indicator=False,
            face_swap_indicator=False,
            suspicious_face_region=False,
            visual_mismatch_indicator=False,
            impersonation_indicators=[],
            analysis_details={
                "note": (
                    "Identity and face matching model "
                    "will be connected later."
                ),
            },
        )

        for item in evidence:

            ImpersonationEvidence.objects.create(
                scan=scan,
                evidence_type="METADATA",
                evidence_value=item,
                risk_contribution=5,
            )

        AuditLog.objects.create(
            user=request.user,
            action="IMPERSONATION_DETECTED",
            ip_address=get_client_ip(request),
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"Image impersonation scan performed. "
                f"Scan ID: {scan.id}"
            ),
            status="SUCCESS",
        )

        return Response(
            {
                "message":
                "Image analysis completed.",

                "scan":
                ImpersonationScanSerializer(
                    scan
                ).data,
            },
            status=status.HTTP_201_CREATED,
        )


class VideoAnalyzeView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

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

        validation_error = validate_uploaded_file(
            uploaded_file,
            VIDEO_EXTENSIONS,
        )

        if validation_error:

            return Response(
                {
                    "detail":
                    validation_error
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        score = 0

        evidence = []

        file_name = uploaded_file.name

        file_size = uploaded_file.size

        extension = os.path.splitext(
            file_name
        )[1].lower()

        # --------------------------------
        # Initial video analysis
        # --------------------------------

        score += 5

        evidence.append(
            "Video submitted for forensic analysis."
        )

        explanation = (
            "Initial video impersonation analysis "
            "completed. Deepfake frame analysis, "
            "face tracking and temporal consistency "
            "models will be connected later."
        )

        result = get_severity(score)

        scan = ImpersonationScan.objects.create(
            user=request.user,
            scan_type="VIDEO",
            file_name=file_name,
            file_size=file_size,
            risk_score=score,
            result=result,
            explanation=explanation,
            status="COMPLETED",
        )

        DeepfakeAnalysis.objects.create(
            scan=scan,
            face_detected=False,
            multiple_faces=False,
            face_manipulation_indicator=False,
            lighting_inconsistency=False,
            edge_artifact_indicator=False,
            compression_anomaly=False,
            metadata_missing=False,
            analysis_details={
                "file_extension": extension,
                "evidence": evidence,
                "note": (
                    "Video deepfake model will be "
                    "connected later."
                ),
            },
        )

        IdentityAnalysis.objects.create(
            scan=scan,
            identity_match_indicator=False,
            face_swap_indicator=False,
            suspicious_face_region=False,
            visual_mismatch_indicator=False,
            impersonation_indicators=[],
            analysis_details={
                "note": (
                    "Video identity analysis model "
                    "will be connected later."
                ),
            },
        )

        for item in evidence:

            ImpersonationEvidence.objects.create(
                scan=scan,
                evidence_type="VIDEO",
                evidence_value=item,
                risk_contribution=5,
            )

        AuditLog.objects.create(
            user=request.user,
            action="DEEPFAKE_DETECTED",
            ip_address=get_client_ip(request),
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"Video deepfake scan performed. "
                f"Scan ID: {scan.id}"
            ),
            status="SUCCESS",
        )

        return Response(
            {
                "message":
                "Video analysis completed.",

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

    serializer_class = ImpersonationScanSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):

        return ImpersonationScan.objects.filter(
            user=self.request.user
        )