from __future__ import annotations

from django.core.management.base import BaseCommand

from anomaly_detection.models import Anomaly, LoginActivity, UserBehaviour
from audit_logs.models import AuditLog
from incidents.models import Incident, IncidentEvidence, ResponseAction
from impersonation.models import (
    DeepfakeAnalysis,
    IdentityAnalysis,
    ImpersonationEvidence,
    ImpersonationScan,
    VoiceAnalysis,
)
from phishing.models import EmailAnalysis, PhishingScan, URLAnalysis
from threat_detection.models import Threat, ThreatAnalysis, ThreatEvidence


class Command(BaseCommand):
    help = (
        "Encrypt sensitive database fields with AES-256-GCM. "
        "Safe to run repeatedly."
    )

    def handle(self, *args, **options):
        models_and_fields = [
            (Threat.objects.all(), ["input_data", "explanation"]),
            (ThreatEvidence.objects.all(), ["evidence_value"]),
            (ThreatAnalysis.objects.all(), ["analysis_result"]),
            (PhishingScan.objects.all(), ["input_data", "explanation"]),
            (URLAnalysis.objects.all(), ["analysis_details"]),
            (EmailAnalysis.objects.all(), ["analysis_details"]),
            (ImpersonationScan.objects.all(), ["explanation"]),
            (DeepfakeAnalysis.objects.all(), ["analysis_details"]),
            (IdentityAnalysis.objects.all(), ["impersonation_indicators", "analysis_details"]),
            (ImpersonationEvidence.objects.all(), ["evidence_value"]),
            (VoiceAnalysis.objects.all(), ["signal_components", "analysis_details"]),
            (Incident.objects.all(), ["description"]),
            (IncidentEvidence.objects.all(), ["evidence_value"]),
            (ResponseAction.objects.all(), ["description"]),
            (AuditLog.objects.all(), ["user_agent", "description"]),
            (UserBehaviour.objects.all(), ["user_agent", "location", "device_id", "activity_data"]),
            (LoginActivity.objects.all(), ["user_agent", "location", "device_id", "failure_reason"]),
            (Anomaly.objects.all(), ["explanation"]),
        ]

        total = 0
        for queryset, fields in models_and_fields:
            for obj in queryset.iterator():
                obj.save(update_fields=fields)
                total += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"AES-256-GCM encryption completed for {total} records."
            )
        )
