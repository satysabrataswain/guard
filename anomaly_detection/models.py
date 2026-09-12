from django.conf import settings
from django.db import models


class UserBehaviour(models.Model):

    ACTIVITY_TYPE_CHOICES = [
        ("LOGIN", "Login"),
        ("LOGOUT", "Logout"),
        ("ACCESS", "Resource Access"),
        ("NETWORK", "Network Activity"),
        ("DEVICE", "Device Activity"),
        ("OTHER", "Other"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="behaviour_records",
    )

    activity_type = models.CharField(
        max_length=30,
        choices=ACTIVITY_TYPE_CHOICES,
    )

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
    )

    user_agent = models.TextField(
        blank=True,
    )

    location = models.CharField(
        max_length=255,
        blank=True,
    )

    device_id = models.CharField(
        max_length=255,
        blank=True,
    )

    activity_data = models.JSONField(
        default=dict,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    def __str__(self):
        return f"{self.user.user_id} - {self.activity_type}"


class LoginActivity(models.Model):

    STATUS_CHOICES = [
        ("SUCCESS", "Success"),
        ("FAILED", "Failed"),
        ("BLOCKED", "Blocked"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="login_activities",
    )

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
    )

    user_agent = models.TextField(
        blank=True,
    )

    location = models.CharField(
        max_length=255,
        blank=True,
    )

    device_id = models.CharField(
        max_length=255,
        blank=True,
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="SUCCESS",
    )

    failure_reason = models.CharField(
        max_length=255,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    def __str__(self):
        return (
            f"{self.user.user_id} - "
            f"{self.status} - "
            f"{self.ip_address}"
        )


class Anomaly(models.Model):

    SEVERITY_CHOICES = [
        ("SAFE", "Safe"),
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]

    STATUS_CHOICES = [
        ("DETECTED", "Detected"),
        ("REVIEWED", "Reviewed"),
        ("RESOLVED", "Resolved"),
        ("FALSE_POSITIVE", "False Positive"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="anomalies",
    )

    anomaly_type = models.CharField(
        max_length=100,
    )

    risk_score = models.FloatField(
        default=0,
    )

    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default="SAFE",
    )

    status = models.CharField(
        max_length=30,
        choices=STATUS_CHOICES,
        default="DETECTED",
    )

    explanation = models.TextField(
        blank=True,
    )

    detected_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    def __str__(self):
        return (
            f"{self.anomaly_type} - "
            f"{self.severity} - "
            f"{self.risk_score}"
        )