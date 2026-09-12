from django.conf import settings
from django.db import models


class PhishingScan(models.Model):

    SCAN_TYPE_CHOICES = [
        ("URL", "URL"),
        ("EMAIL", "Email"),
    ]

    RESULT_CHOICES = [
        ("SAFE", "Safe"),
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]

    STATUS_CHOICES = [
        ("COMPLETED", "Completed"),
        ("FAILED", "Failed"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="phishing_scans",
    )

    scan_type = models.CharField(
        max_length=20,
        choices=SCAN_TYPE_CHOICES,
    )

    input_data = models.TextField()

    risk_score = models.FloatField(
        default=0,
    )

    result = models.CharField(
        max_length=20,
        choices=RESULT_CHOICES,
        default="SAFE",
    )

    explanation = models.TextField(
        blank=True,
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="COMPLETED",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    def __str__(self):
        return (
            f"{self.scan_type} - "
            f"{self.result} - "
            f"{self.risk_score}"
        )


class URLAnalysis(models.Model):

    scan = models.OneToOneField(
        PhishingScan,
        on_delete=models.CASCADE,
        related_name="url_analysis",
    )

    domain = models.CharField(
        max_length=255,
        blank=True,
    )

    uses_https = models.BooleanField(
        default=False,
    )

    url_length = models.PositiveIntegerField(
        default=0,
    )

    has_ip_address = models.BooleanField(
        default=False,
    )

    has_suspicious_keyword = models.BooleanField(
        default=False,
    )

    has_shortener = models.BooleanField(
        default=False,
    )

    redirect_count = models.PositiveIntegerField(
        default=0,
    )

    analysis_details = models.JSONField(
        default=dict,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    def __str__(self):
        return f"URL Analysis - {self.domain}"


class EmailAnalysis(models.Model):

    scan = models.OneToOneField(
        PhishingScan,
        on_delete=models.CASCADE,
        related_name="email_analysis",
    )

    sender = models.EmailField(
        blank=True,
    )

    subject = models.CharField(
        max_length=500,
        blank=True,
    )

    has_suspicious_keyword = models.BooleanField(
        default=False,
    )

    has_urgent_language = models.BooleanField(
        default=False,
    )

    has_suspicious_link = models.BooleanField(
        default=False,
    )

    has_attachment_warning = models.BooleanField(
        default=False,
    )

    analysis_details = models.JSONField(
        default=dict,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    def __str__(self):
        return f"Email Analysis - {self.subject}"