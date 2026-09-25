from rest_framework import serializers

from .models import (
    UserBehaviour,
    LoginActivity,
    Anomaly,
)


class UserBehaviourSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserBehaviour
        fields = "__all__"
        read_only_fields = ["id", "user", "created_at"]


class LoginActivitySerializer(serializers.ModelSerializer):

    class Meta:
        model = LoginActivity
        fields = "__all__"
        read_only_fields = ["id", "user", "created_at"]


class AnomalySerializer(serializers.ModelSerializer):

    class Meta:
        model = Anomaly
        fields = "__all__"
        read_only_fields = [
            "id",
            "user",
            "risk_score",
            "severity",
            "explanation",
            "detected_at",
            "updated_at",
        ]