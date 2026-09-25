from django.conf import settings
from django.db import models

from security.fields import EncryptedTextField


class Incident(models.Model):

    SEVERITY_CHOICES = [
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]

    STATUS_CHOICES = [
        ("OPEN", "Open"),
        ("INVESTIGATING", "Investigating"),
        ("CONTAINED", "Contained"),
        ("RESOLVED", "Resolved"),
        ("FALSE_POSITIVE", "False Positive"),
    ]

    incident_type = models.CharField(
        max_length=100
    )

    title = models.CharField(
        max_length=255
    )

    description = EncryptedTextField(
        blank=True
    )

    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default="MEDIUM"
    )

    status = models.CharField(
        max_length=30,
        choices=STATUS_CHOICES,
        default="OPEN"
    )

    risk_score = models.FloatField(
        default=0
    )

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_incidents"
    )

    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_incidents"
    )

    source_type = models.CharField(
        max_length=50,
        blank=True
    )

    source_id = models.PositiveIntegerField(
        null=True,
        blank=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        auto_now=True
    )

    resolved_at = models.DateTimeField(
        null=True,
        blank=True
    )

    def __str__(self):
        return (
            f"{self.title} - "
            f"{self.severity} - "
            f"{self.status}"
        )


class IncidentEvidence(models.Model):

    incident = models.ForeignKey(
        Incident,
        on_delete=models.CASCADE,
        related_name="evidence"
    )

    evidence_type = models.CharField(
        max_length=100
    )

    evidence_value = EncryptedTextField(
        blank=True
    )

    risk_contribution = models.FloatField(
        default=0
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return (
            f"{self.incident.title} - "
            f"{self.evidence_type}"
        )


class ResponseAction(models.Model):

    ACTION_CHOICES = [
        ("BLOCK_URL", "Block URL"),
        ("QUARANTINE_EMAIL", "Quarantine Email"),
        ("REVOKE_SESSION", "Revoke Session"),
        ("STRENGTHEN_AUTH", "Strengthen Authentication"),
        ("ALERT_USER", "Alert User"),
        ("ALERT_ADMIN", "Alert Administrator"),
        ("ESCALATE", "Escalate Incident"),
        ("ISOLATE_DEVICE", "Isolate Device"),
        ("MONITOR", "Monitor"),
        ("OTHER", "Other"),
    ]

    STATUS_CHOICES = [
        ("PENDING", "Pending"),
        ("EXECUTED", "Executed"),
        ("FAILED", "Failed"),
        ("CANCELLED", "Cancelled"),
    ]

    incident = models.ForeignKey(
        Incident,
        on_delete=models.CASCADE,
        related_name="response_actions"
    )

    action_type = models.CharField(
        max_length=50,
        choices=ACTION_CHOICES
    )

    description = EncryptedTextField(
        blank=True
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="PENDING"
    )

    executed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="executed_response_actions"
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    executed_at = models.DateTimeField(
        null=True,
        blank=True
    )

    def __str__(self):
        return (
            f"{self.incident.title} - "
            f"{self.action_type} - "
            f"{self.status}"
        )