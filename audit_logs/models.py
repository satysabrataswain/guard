from django.conf import settings
from django.db import models


class AuditLog(models.Model):

    ACTION_CHOICES = [
        ("LOGIN", "Login"),
        ("FAILED_LOGIN", "Failed Login"),
        ("LOGOUT", "Logout"),
        ("REGISTER", "Register"),
        ("CAPTCHA_FAILED", "Captcha Failed"),

        ("THREAT_ANALYZED", "Threat Analyzed"),

        ("PHISHING_SCAN", "Phishing Scan"),
        ("URL_BLOCKED", "URL Blocked"),
        ("EMAIL_QUARANTINED", "Email Quarantined"),

        ("IMPERSONATION_DETECTED", "Impersonation Detected"),
        ("DEEPFAKE_DETECTED", "Deepfake Detected"),

        ("ANOMALY_DETECTED", "Anomaly Detected"),

        ("INCIDENT_CREATED", "Incident Created"),
        ("INCIDENT_UPDATED", "Incident Updated"),
        ("INCIDENT_RESOLVED", "Incident Resolved"),

        ("SESSION_REVOKED", "Session Revoked"),

        ("USER_CREATED", "User Created"),
        ("USER_UPDATED", "User Updated"),
        ("USER_DELETED", "User Deleted"),

        ("SETTINGS_CHANGED", "Settings Changed"),
    ]

    STATUS_CHOICES = [
        ("SUCCESS", "Success"),
        ("FAILED", "Failed"),
        ("BLOCKED", "Blocked"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
    )

    action = models.CharField(
        max_length=50,
        choices=ACTION_CHOICES,
    )

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
    )

    user_agent = models.TextField(
        blank=True,
    )

    resource = models.CharField(
        max_length=255,
        blank=True,
    )

    resource_id = models.PositiveIntegerField(
        null=True,
        blank=True,
    )

    description = models.TextField(
        blank=True,
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="SUCCESS",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        user_id = (
            self.user.user_id
            if self.user
            else "SYSTEM"
        )

        return (
            f"{user_id} - "
            f"{self.action} - "
            f"{self.status}"
        )