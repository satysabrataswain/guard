from rest_framework import serializers

from .models import (
    ImpersonationScan,
    DeepfakeAnalysis,
    IdentityAnalysis,
    ImpersonationEvidence,
)


class DeepfakeAnalysisSerializer(
    serializers.ModelSerializer
):

    class Meta:
        model = DeepfakeAnalysis

        fields = [
            "id",
            "face_detected",
            "multiple_faces",
            "face_manipulation_indicator",
            "lighting_inconsistency",
            "edge_artifact_indicator",
            "compression_anomaly",
            "metadata_missing",
            "analysis_details",
            "created_at",
        ]

        read_only_fields = [
            "id",
            "created_at",
        ]


class IdentityAnalysisSerializer(
    serializers.ModelSerializer
):

    class Meta:
        model = IdentityAnalysis

        fields = [
            "id",
            "identity_match_indicator",
            "face_swap_indicator",
            "suspicious_face_region",
            "visual_mismatch_indicator",
            "impersonation_indicators",
            "analysis_details",
            "created_at",
        ]

        read_only_fields = [
            "id",
            "created_at",
        ]


class ImpersonationEvidenceSerializer(
    serializers.ModelSerializer
):

    class Meta:
        model = ImpersonationEvidence

        fields = [
            "id",
            "evidence_type",
            "evidence_value",
            "risk_contribution",
            "created_at",
        ]

        read_only_fields = [
            "id",
            "created_at",
        ]


class ImpersonationScanSerializer(
    serializers.ModelSerializer
):

    deepfake_analysis = DeepfakeAnalysisSerializer(
        read_only=True
    )

    identity_analysis = IdentityAnalysisSerializer(
        read_only=True
    )

    evidence = ImpersonationEvidenceSerializer(
        many=True,
        read_only=True
    )

    class Meta:
        model = ImpersonationScan

        fields = [
            "id",
            "user",
            "scan_type",
            "file_name",
            "file_size",
            "risk_score",
            "result",
            "explanation",
            "status",
            "created_at",
            "updated_at",
            "deepfake_analysis",
            "identity_analysis",
            "evidence",
        ]

        read_only_fields = [
            "id",
            "user",
            "risk_score",
            "result",
            "explanation",
            "status",
            "created_at",
            "updated_at",
            "deepfake_analysis",
            "identity_analysis",
            "evidence",
        ]