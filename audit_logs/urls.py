from django.urls import path

from .views import (
    MyAuditLogView,
    AdminAuditLogView,
)


urlpatterns = [

    path(
        "my/",
        MyAuditLogView.as_view(),
        name="my-audit-logs",
    ),

    path(
        "admin/",
        AdminAuditLogView.as_view(),
        name="admin-audit-logs",
    ),
]