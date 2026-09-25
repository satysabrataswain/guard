from rest_framework import serializers

from .models import (
    Threat,
    ThreatEvidence,
    ThreatAnalysis,
)


class ThreatEvidenceSerializer(serializers.ModelSerializer):

    class Meta:
        model = ThreatEvidence

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


class ThreatAnalysisSerializer(serializers.ModelSerializer):

    class Meta:
        model = ThreatAnalysis

        fields = [
            "id",
            "model_name",
            "model_version",
            "prediction",
            "confidence",
            "score",
            "analysis_result",
            "created_at",
        ]

        read_only_fields = [
            "id",
            "created_at",
        ]


class ThreatSerializer(serializers.ModelSerializer):

    evidence = ThreatEvidenceSerializer(
        many=True,
        read_only=True,
    )

    analyses = ThreatAnalysisSerializer(
        many=True,
        read_only=True,
    )

    class Meta:
        model = Threat

        fields = [
            "id",
            "user",
            "threat_type",
            "source_type",
            "input_data",
            "risk_score",
            "severity",
            "status",
            "explanation",
            "detected_at",
            "updated_at",
            "evidence",
            "analyses",
        ]

        read_only_fields = [
            "id",
            "user",
            "risk_score",
            "severity",
            "status",
            "explanation",
            "detected_at",
            "updated_at",
            "evidence",
            "analyses",
        ]
