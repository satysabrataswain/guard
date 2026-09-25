from django.urls import path

from .views import (
    AuditLogListView,
    AuditLogDetailView,
    MyAuditLogListView,
    AdminAuditLogListView,
)


urlpatterns = [
    # General audit logs
    path(
        "",
        AuditLogListView.as_view(),
        name="audit-list",
    ),

    # Admin-only audit logs
    path(
        "admin/",
        AdminAuditLogListView.as_view(),
        name="audit-admin",
    ),

    # Current user's own audit logs
    path(
        "my/",
        MyAuditLogListView.as_view(),
        name="audit-my",
    ),

    # Individual audit log
    path(
        "<int:pk>/",
        AuditLogDetailView.as_view(),
        name="audit-detail",
    ),
]