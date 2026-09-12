from rest_framework import serializers

from .models import AuditLog


class AuditLogSerializer(
    serializers.ModelSerializer
):

    user_id = serializers.CharField(
        source="user.user_id",
        read_only=True,
    )

    class Meta:
        model = AuditLog

        fields = [
            "id",
            "user",
            "user_id",
            "action",
            "ip_address",
            "user_agent",
            "resource",
            "resource_id",
            "description",
            "status",
            "created_at",
        ]

        read_only_fields = [
            "id",
            "user",
            "user_id",
            "ip_address",
            "user_agent",
            "resource",
            "resource_id",
            "description",
            "status",
            "created_at",
        ]