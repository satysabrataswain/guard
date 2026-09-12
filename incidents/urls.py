from django.urls import path

from .views import (
    IncidentListCreateView,
    IncidentDetailView,
    IncidentDeleteView,
    IncidentEvidenceView,
    ResponseActionView,
    ExecuteResponseActionView,
    ResolveIncidentView,
)


urlpatterns = [

    path(
        "",
        IncidentListCreateView.as_view(),
        name="incident-list-create",
    ),

    path(
        "<int:pk>/",
        IncidentDetailView.as_view(),
        name="incident-detail",
    ),

    path(
        "<int:pk>/delete/",
        IncidentDeleteView.as_view(),
        name="incident-delete",
    ),

    path(
        "<int:pk>/evidence/",
        IncidentEvidenceView.as_view(),
        name="incident-evidence",
    ),

    path(
        "<int:pk>/response/",
        ResponseActionView.as_view(),
        name="response-action",
    ),

    path(
        "response/<int:pk>/execute/",
        ExecuteResponseActionView.as_view(),
        name="execute-response",
    ),

    path(
        "<int:pk>/resolve/",
        ResolveIncidentView.as_view(),
        name="resolve-incident",
    ),
]