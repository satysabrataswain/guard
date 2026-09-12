from django.contrib import admin

from .models import (
Threat,
ThreatEvidence,
ThreatAnalysis,
)

class ThreatEvidenceInline(admin.TabularInline):


 model = ThreatEvidence
extra = 0

readonly_fields = (
    "created_at",
)


class ThreatAnalysisInline(admin.TabularInline):


 model = ThreatAnalysis
 extra = 0

readonly_fields = (
    "created_at",
)


@admin.register(Threat)
class ThreatAdmin(admin.ModelAdmin):


 list_display = (
    "id",
    "user",
    "threat_type",
    "source_type",
    "risk_score",
    "severity",
    "status",
    "detected_at",
)

list_filter = (
    "threat_type",
    "source_type",
    "severity",
    "status",
    "detected_at",
)

search_fields = (
    "user__user_id",
    "user__email",
    "input_data",
    "explanation",
)

ordering = (
    "-detected_at",
)

readonly_fields = (
    "risk_score",
    "severity",
    "explanation",
    "detected_at",
    "updated_at",
)

inlines = [
    ThreatEvidenceInline,
    ThreatAnalysisInline,
]


@admin.register(ThreatEvidence)
class ThreatEvidenceAdmin(admin.ModelAdmin):


 list_display = (
    "id",
    "threat",
    "evidence_type",
    "risk_contribution",
    "created_at",
)

list_filter = (
    "evidence_type",
    "created_at",
)

search_fields = (
    "evidence_type",
    "evidence_value",
    "threat__input_data",
)

readonly_fields = (
    "created_at",
)


@admin.register(ThreatAnalysis)
class ThreatAnalysisAdmin(admin.ModelAdmin):


 list_display = (
    "id",
    "threat",
    "model_name",
    "model_version",
    "prediction",
    "confidence",
    "score",
    "created_at",
)

list_filter = (
    "model_name",
    "prediction",
    "created_at",
)

search_fields = (
    "model_name",
    "prediction",
    "threat__input_data",
)

readonly_fields = (
    "created_at",
)
