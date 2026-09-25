from __future__ import annotations

from django.conf import settings
from django.db import models

from .fields import EncryptedJSONField


class BrowserPrivacyPairing(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="browser_privacy_pairings",
    )
    code_hash = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "expires_at"]),
        ]

    def __str__(self) -> str:
        return f"Browser privacy pairing for {self.user_id}"


class BrowserPrivacyScan(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="browser_privacy_scans",
    )
    browser = models.CharField(max_length=100, blank=True)
    browser_version = models.CharField(max_length=100, blank=True)
    platform = models.CharField(max_length=150, blank=True)
    cookie_count = models.PositiveIntegerField(default=0)
    sensitive_cookie_count = models.PositiveIntegerField(default=0)
    extension_count = models.PositiveIntegerField(default=0)
    high_impact_extension_count = models.PositiveIntegerField(default=0)
    cookie_metadata = EncryptedJSONField(default=list, blank=True)
    extension_metadata = EncryptedJSONField(default=list, blank=True)
    summary = EncryptedJSONField(default=dict, blank=True)
    scanned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-scanned_at"]
        indexes = [
            models.Index(fields=["user", "-scanned_at"]),
        ]

    def __str__(self) -> str:
        return f"Browser privacy scan {self.id} for {self.user_id}"
