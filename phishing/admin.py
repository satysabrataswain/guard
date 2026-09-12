from django.contrib import admin

from .models import (
    PhishingScan,
    URLAnalysis,
    EmailAnalysis,
)


class URLAnalysisInline(admin.StackedInline):

    model = URLAnalysis
    extra = 0

    readonly_fields = (
        "created_at",
    )


class EmailAnalysisInline(admin.StackedInline):

    model = EmailAnalysis
    extra = 0

    readonly_fields = (
        "created_at",
    )


@admin.register(PhishingScan)
class PhishingScanAdmin(admin.ModelAdmin):

    list_display = (
        "id",
        "user",
        "scan_type",
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
        "input_data",
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
        URLAnalysisInline,
        EmailAnalysisInline,
    ]


@admin.register(URLAnalysis)
class URLAnalysisAdmin(admin.ModelAdmin):

    list_display = (
        "id",
        "scan",
        "domain",
        "uses_https",
        "has_ip_address",
        "has_suspicious_keyword",
        "has_shortener",
        "created_at",
    )

    list_filter = (
        "uses_https",
        "has_ip_address",
        "has_suspicious_keyword",
        "has_shortener",
    )

    search_fields = (
        "domain",
        "scan__input_data",
    )

    readonly_fields = (
        "created_at",
    )


@admin.register(EmailAnalysis)
class EmailAnalysisAdmin(admin.ModelAdmin):

    list_display = (
        "id",
        "scan",
        "sender",
        "subject",
        "has_suspicious_keyword",
        "has_urgent_language",
        "has_suspicious_link",
        "created_at",
    )

    list_filter = (
        "has_suspicious_keyword",
        "has_urgent_language",
        "has_suspicious_link",
        "has_attachment_warning",
    )

    search_fields = (
        "sender",
        "subject",
        "scan__input_data",
    )

    readonly_fields = (
        "created_at",
    )