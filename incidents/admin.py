from django.contrib import admin

from .models import (
    Incident,
    IncidentEvidence,
    ResponseAction,
)


class IncidentEvidenceInline(
    admin.TabularInline
):
    model = IncidentEvidence
    extra = 0


class ResponseActionInline(
    admin.TabularInline
):
    model = ResponseAction
    extra = 0


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):

    list_display = (
        "id",
        "title",
        "incident_type",
        "severity",
        "status",
        "risk_score",
        "created_by",
        "assigned_to",
        "created_at",
    )

    list_filter = (
        "severity",
        "status",
        "incident_type",
    )

    search_fields = (
        "title",
        "description",
        "incident_type",
        "created_by__user_id",
        "created_by__email",
    )

    readonly_fields = (
        "created_at",
        "updated_at",
        "resolved_at",
    )

    inlines = [
        IncidentEvidenceInline,
        ResponseActionInline,
    ]


@admin.register(IncidentEvidence)
class IncidentEvidenceAdmin(admin.ModelAdmin):

    list_display = (
        "id",
        "incident",
        "evidence_type",
        "risk_contribution",
        "created_at",
    )

    search_fields = (
        "incident__title",
        "evidence_type",
        "evidence_value",
    )

    readonly_fields = (
        "created_at",
    )


@admin.register(ResponseAction)
class ResponseActionAdmin(admin.ModelAdmin):

    list_display = (
        "id",
        "incident",
        "action_type",
        "status",
        "executed_by",
        "created_at",
        "executed_at",
    )

    list_filter = (
        "action_type",
        "status",
    )

    search_fields = (
        "incident__title",
        "description",
    )

    readonly_fields = (
        "created_at",
        "executed_at",
    )