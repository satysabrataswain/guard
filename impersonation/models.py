from django.conf import settings
from django.db import models

from security.fields import EncryptedJSONField, EncryptedTextField


class ImpersonationScan(models.Model):

    SCAN_TYPE_CHOICES = [
        ("IMAGE", "Image"),
        ("VIDEO", "Video"),
        ("VOICE", "Voice"),
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
        related_name="impersonation_scans",
    )

    scan_type = models.CharField(
        max_length=20,
        choices=SCAN_TYPE_CHOICES,
    )

    file_name = models.CharField(
        max_length=255,
        blank=True,
    )

    file_size = models.PositiveBigIntegerField(
        default=0,
    )

    risk_score = models.FloatField(
        default=0,
    )

    result = models.CharField(
        max_length=20,
        choices=RESULT_CHOICES,
        default="SAFE",
    )

    explanation = EncryptedTextField(
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


class DeepfakeAnalysis(models.Model):

    scan = models.OneToOneField(
        ImpersonationScan,
        on_delete=models.CASCADE,
        related_name="deepfake_analysis",
    )

    face_detected = models.BooleanField(
        default=False,
    )

    multiple_faces = models.BooleanField(
        default=False,
    )

    face_manipulation_indicator = models.BooleanField(
        default=False,
    )

    lighting_inconsistency = models.BooleanField(
        default=False,
    )

    edge_artifact_indicator = models.BooleanField(
        default=False,
    )

    compression_anomaly = models.BooleanField(
        default=False,
    )

    metadata_missing = models.BooleanField(
        default=False,
    )

    analysis_details = EncryptedJSONField(
        default=dict,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    def __str__(self):
        return (
            f"Deepfake Analysis - "
            f"{self.scan.id}"
        )


class IdentityAnalysis(models.Model):

    scan = models.OneToOneField(
        ImpersonationScan,
        on_delete=models.CASCADE,
        related_name="identity_analysis",
    )

    identity_match_indicator = models.BooleanField(
        default=False,
    )

    face_swap_indicator = models.BooleanField(
        default=False,
    )

    suspicious_face_region = models.BooleanField(
        default=False,
    )

    visual_mismatch_indicator = models.BooleanField(
        default=False,
    )

    impersonation_indicators = EncryptedJSONField(
        default=list,
        blank=True,
    )

    analysis_details = EncryptedJSONField(
        default=dict,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    def __str__(self):
        return (
            f"Identity Analysis - "
            f"{self.scan.id}"
        )


class ImpersonationEvidence(models.Model):

    scan = models.ForeignKey(
        ImpersonationScan,
        on_delete=models.CASCADE,
        related_name="evidence",
    )

    evidence_type = models.CharField(
        max_length=100,
    )

    evidence_value = models.TextField(
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
            f"{self.evidence_type} - "
            f"{self.risk_contribution}"
        )

class VoiceAnalysis(models.Model):

    scan = models.OneToOneField(
        ImpersonationScan,
        on_delete=models.CASCADE,
        related_name="voice_analysis",
    )

    duration_seconds = models.FloatField(default=0)
    sample_rate = models.PositiveIntegerField(default=16000)
    speech_ratio = models.FloatField(default=0)
    silence_ratio = models.FloatField(default=0)
    pitch_mean_hz = models.FloatField(default=0)
    pitch_std_hz = models.FloatField(default=0)
    pitch_range_hz = models.FloatField(default=0)
    pitch_variation_cv = models.FloatField(default=0)
    spectral_centroid_mean_hz = models.FloatField(default=0)
    spectral_centroid_std_hz = models.FloatField(default=0)
    spectral_bandwidth_std_hz = models.FloatField(default=0)
    spectral_flatness_mean = models.FloatField(default=0)
    spectral_flatness_std = models.FloatField(default=0)
    mfcc_variability = models.FloatField(default=0)
    mfcc_delta_variability = models.FloatField(default=0)
    energy_std_db = models.FloatField(default=0)
    energy_range_db = models.FloatField(default=0)
    zero_crossing_std = models.FloatField(default=0)
    spectral_flux_std = models.FloatField(default=0)
    harmonic_ratio = models.FloatField(default=0)
    clipping_ratio = models.FloatField(default=0)
    voiced_frame_ratio = models.FloatField(default=0)

    synthetic_voice_indicator = models.BooleanField(default=False)
    replay_indicator = models.BooleanField(default=False)

    signal_components = EncryptedJSONField(default=dict, blank=True)
    analysis_details = EncryptedJSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Voice Analysis - {self.scan.id}"
