from django.contrib import admin

from .models import (
    ImpersonationScan,
    DeepfakeAnalysis,
    IdentityAnalysis,
    ImpersonationEvidence,
)


class DeepfakeAnalysisInline(
    admin.StackedInline
):

    model = DeepfakeAnalysis

    extra = 0

    readonly_fields = (
        "created_at",
    )


class IdentityAnalysisInline(
    admin.StackedInline
):

    model = IdentityAnalysis

    extra = 0

    readonly_fields = (
        "created_at",
    )


class ImpersonationEvidenceInline(
    admin.TabularInline
):

    model = ImpersonationEvidence

    extra = 0

    readonly_fields = (
        "created_at",
    )


@admin.register(ImpersonationScan)
class ImpersonationScanAdmin(
    admin.ModelAdmin
):

    list_display = (
        "id",
        "user",
        "scan_type",
        "file_name",
        "risk_score",
        "result",
        "status",
        "created_at",
    )

    list_filter = (
        "scan_type",
        "result",
        "status",
        "created_at",
    )

    search_fields = (
        "user__user_id",
        "user__email",
        "file_name",
        "explanation",
    )

    ordering = (
        "-created_at",
    )

    readonly_fields = (
        "user",
        "risk_score",
        "result",
        "explanation",
        "status",
        "created_at",
        "updated_at",
    )

    inlines = [
        DeepfakeAnalysisInline,
        IdentityAnalysisInline,
        ImpersonationEvidenceInline,
    ]


@admin.register(DeepfakeAnalysis)
class DeepfakeAnalysisAdmin(
    admin.ModelAdmin
):

    list_display = (
        "id",
        "scan",
        "face_detected",
        "face_manipulation_indicator",
        "lighting_inconsistency",
        "edge_artifact_indicator",
        "compression_anomaly",
        "metadata_missing",
        "created_at",
    )

    list_filter = (
        "face_detected",
        "face_manipulation_indicator",
        "lighting_inconsistency",
        "edge_artifact_indicator",
        "compression_anomaly",
        "metadata_missing",
    )

    readonly_fields = (
        "created_at",
    )


@admin.register(IdentityAnalysis)
class IdentityAnalysisAdmin(
    admin.ModelAdmin
):

    list_display = (
        "id",
        "scan",
        "identity_match_indicator",
        "face_swap_indicator",
        "suspicious_face_region",
        "visual_mismatch_indicator",
        "created_at",
    )

    list_filter = (
        "identity_match_indicator",
        "face_swap_indicator",
        "suspicious_face_region",
        "visual_mismatch_indicator",
    )

    readonly_fields = (
        "created_at",
    )


@admin.register(ImpersonationEvidence)
class ImpersonationEvidenceAdmin(
    admin.ModelAdmin
):

    list_display = (
        "id",
        "scan",
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
        "scan__file_name",
    )

    readonly_fields = (
        "created_at",
    )