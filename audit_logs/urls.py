
from django.urls import path

from .views import (
    AuditLogDetailView,
    AuditLogListView,
    MyAuditLogListView,
)

urlpatterns = [
    path("",AuditLogListView.as_view(),name="audit-log-list", ),
    path(
        "mine/",
        MyAuditLogListView.as_view(),
        name="my-audit-log-list",
    ),
    path(
        "<int:pk>/",
        AuditLogDetailView.as_view(),
        name="audit-log-detail",
    ),
]
