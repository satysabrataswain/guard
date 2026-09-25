from rest_framework import serializers

from .models import (
    Incident,
    IncidentEvidence,
    ResponseAction,
)


class IncidentEvidenceSerializer(
    serializers.ModelSerializer
):

    class Meta:
        model = IncidentEvidence
        fields = "__all__"

        read_only_fields = [
            "id",
            "incident",
            "created_at",
        ]


class ResponseActionSerializer(
    serializers.ModelSerializer
):

    class Meta:
        model = ResponseAction
        fields = "__all__"

        read_only_fields = [
            "id",
            "incident",
            "executed_by",
            "created_at",
            "executed_at",
        ]


class IncidentSerializer(
    serializers.ModelSerializer
):

    evidence = IncidentEvidenceSerializer(
        many=True,
        read_only=True
    )

    response_actions = ResponseActionSerializer(
        many=True,
        read_only=True
    )

    class Meta:
        model = Incident

        fields = [
            "id",
            "incident_type",
            "title",
            "description",
            "severity",
            "status",
            "risk_score",
            "created_by",
            "assigned_to",
            "source_type",
            "source_id",
            "created_at",
            "updated_at",
            "resolved_at",
            "evidence",
            "response_actions",
        ]

        read_only_fields = [
            "id",
            "created_by",
            "created_at",
            "updated_at",
            "resolved_at",
            "evidence",
            "response_actions",
        ]