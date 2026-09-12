from django.contrib import admin

from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):

    list_display = (
        "id",
        "user",
        "action",
        "status",
        "ip_address",
        "resource",
        "resource_id",
        "created_at",
    )

    list_filter = (
        "action",
        "status",
        "created_at",
    )

    search_fields = (
        "user__user_id",
        "user__email",
        "ip_address",
        "resource",
        "description",
    )

    readonly_fields = (
        "user",
        "action",
        "ip_address",
        "user_agent",
        "resource",
        "resource_id",
        "description",
        "status",
        "created_at",
    )

    def has_add_permission(
        self,
        request
    ):
        return False

    def has_change_permission(
        self,
        request,
        obj=None
    ):
        return False

    def has_delete_permission(
        self,
        request,
        obj=None
    ):
        return False