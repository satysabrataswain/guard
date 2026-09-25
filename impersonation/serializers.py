from rest_framework import serializers

from .models import (
    ImpersonationScan,
    DeepfakeAnalysis,
    IdentityAnalysis,
    ImpersonationEvidence,
    VoiceAnalysis,
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


class VoiceAnalysisSerializer(
    serializers.ModelSerializer
):

    class Meta:
        model = VoiceAnalysis
        fields = [
            "id",
            "duration_seconds",
            "sample_rate",
            "speech_ratio",
            "silence_ratio",
            "pitch_mean_hz",
            "pitch_std_hz",
            "pitch_range_hz",
            "pitch_variation_cv",
            "spectral_centroid_mean_hz",
            "spectral_centroid_std_hz",
            "spectral_bandwidth_std_hz",
            "spectral_flatness_mean",
            "spectral_flatness_std",
            "mfcc_variability",
            "mfcc_delta_variability",
            "energy_std_db",
            "energy_range_db",
            "zero_crossing_std",
            "spectral_flux_std",
            "harmonic_ratio",
            "clipping_ratio",
            "voiced_frame_ratio",
            "synthetic_voice_indicator",
            "replay_indicator",
            "signal_components",
            "analysis_details",
            "created_at",
        ]
        read_only_fields = ["id", "created_at"]


class ImpersonationScanSerializer(
    serializers.ModelSerializer
):

    deepfake_analysis = DeepfakeAnalysisSerializer(
        read_only=True
    )

    identity_analysis = IdentityAnalysisSerializer(
        read_only=True
    )

    voice_analysis = VoiceAnalysisSerializer(
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
            "voice_analysis",
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
            "voice_analysis",
            "evidence",
        ]