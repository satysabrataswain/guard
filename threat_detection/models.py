from django.conf import settings
from django.db import models

from security.fields import EncryptedJSONField, EncryptedTextField


class Threat(models.Model):

    THREAT_TYPE_CHOICES = [
        ("PHISHING", "Phishing"),
        ("MALICIOUS_URL", "Malicious URL"),
        ("SUSPICIOUS_EMAIL", "Suspicious Email"),
        ("SUSPICIOUS_MESSAGE", "Suspicious Message"),
        ("DEEPFAKE", "Deepfake"),
        ("IMAGE_MANIPULATION", "Image Manipulation"),
        ("ANOMALY", "Anomaly"),
        ("ACCOUNT_TAKEOVER", "Account Takeover"),
        ("MALICIOUS_FILE", "Malicious File"),
        ("NETWORK_THREAT", "Network Threat"),
        ("OTHER", "Other"),
    ]

    SOURCE_TYPE_CHOICES = [
        ("URL", "URL"),
        ("EMAIL", "Email"),
        ("MESSAGE", "Message"),
        ("IMAGE", "Image"),
        ("VIDEO", "Video"),
        ("VOICE", "Voice"),
        ("LOGIN", "Login Activity"),
        ("DEVICE", "Device Activity"),
        ("NETWORK", "Network Activity"),
        ("FILE", "File"),
        ("OTHER", "Other"),
    ]

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
        related_name="threats",
    )

    threat_type = models.CharField(
        max_length=50,
        choices=THREAT_TYPE_CHOICES,
    )

    source_type = models.CharField(
        max_length=30,
        choices=SOURCE_TYPE_CHOICES,
    )

    input_data = EncryptedTextField(
        blank=True,
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

    explanation = EncryptedTextField(
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
            f"{self.threat_type} - "
            f"{self.severity} - "
            f"{self.risk_score}"
        )


class ThreatEvidence(models.Model):

    threat = models.ForeignKey(
        Threat,
        on_delete=models.CASCADE,
        related_name="evidence",
    )

    evidence_type = models.CharField(
        max_length=100,
    )

    evidence_value = EncryptedTextField(
        blank=True,
    )

    risk_contribution = models.FloatField(
        default=0,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    def __str__(self):
        return (
            f"{self.evidence_type} "
            f"({self.risk_contribution})"
        )


class ThreatAnalysis(models.Model):

    threat = models.ForeignKey(
        Threat,
        on_delete=models.CASCADE,
        related_name="analyses",
    )

    model_name = models.CharField(
        max_length=100,
    )

    model_version = models.CharField(
        max_length=50,
        blank=True,
    )

    prediction = models.CharField(
        max_length=100,
    )

    confidence = models.FloatField(
        default=0,
    )

    score = models.FloatField(
        default=0,
    )

    analysis_result = EncryptedJSONField(
        default=dict,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    def __str__(self):
        return (
            f"{self.model_name} - "
            f"{self.prediction} - "
            f"{self.confidence}"
        )