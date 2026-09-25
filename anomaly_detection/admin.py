from django.contrib import admin

from .models import (
    UserBehaviour,
    LoginActivity,
    Anomaly,
)


@admin.register(UserBehaviour)
class UserBehaviourAdmin(admin.ModelAdmin):

    list_display = (
        "id",
        "user",
        "activity_type",
        "ip_address",
        "location",
        "device_id",
        "created_at",
    )

    list_filter = (
        "activity_type",
        "created_at",
    )

    search_fields = (
        "user__user_id",
        "user__email",
        "ip_address",
        "location",
        "device_id",
    )

    readonly_fields = (
        "created_at",
    )


@admin.register(LoginActivity)
class LoginActivityAdmin(admin.ModelAdmin):

    list_display = (
        "id",
        "user",
        "status",
        "ip_address",
        "location",
        "device_id",
        "created_at",
    )

    list_filter = (
        "status",
        "created_at",
    )

    search_fields = (
        "user__user_id",
        "user__email",
        "ip_address",
        "location",
        "device_id",
    )

    readonly_fields = (
        "created_at",
    )


@admin.register(Anomaly)
class AnomalyAdmin(admin.ModelAdmin):

    list_display = (
        "id",
        "user",
        "anomaly_type",
        "risk_score",
        "severity",
        "status",
        "detected_at",
    )

    list_filter = (
        "severity",
        "status",
        "anomaly_type",
    )

    search_fields = (
        "user__user_id",
        "user__email",
        "anomaly_type",
        "explanation",
    )

    readonly_fields = (
        "detected_at",
        "updated_at",
    )