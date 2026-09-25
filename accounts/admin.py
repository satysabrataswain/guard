from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import User


@admin.register(User)
class CustomUserAdmin(UserAdmin):

    list_display = (
        "user_id",
        "first_name",
        "last_name",
        "email",
        "phone_number",
        "role",
        "is_active",
        "created_at",
    )

    list_filter = (
        "role",
        "is_active",
        "created_at",
    )

    search_fields = (
        "user_id",
        "first_name",
        "last_name",
        "email",
        "phone_number",
    )

    ordering = ("-created_at",)

    fieldsets = UserAdmin.fieldsets + (
        (
            "Cyber Security Account",
            {
                "fields": (
                    "user_id",
                    "phone_number",
                    "role",
                    "created_at",
                    "updated_at",
                )
            },
        ),
    )

    readonly_fields = (
        "created_at",
        "updated_at",
    )