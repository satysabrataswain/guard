from django.urls import path

from .views import (
    ImpersonationHistoryView,
    ImpersonationDetailView,
    ImageAnalyzeView,
    VideoAnalyzeView,
    ImpersonationDeleteView,
)


urlpatterns = [

    path(
        "image/analyze/",
        ImageAnalyzeView.as_view(),
        name="image-analyze",
    ),

    path(
        "video/analyze/",
        VideoAnalyzeView.as_view(),
        name="video-analyze",
    ),

    path(
        "history/",
        ImpersonationHistoryView.as_view(),
        name="impersonation-history",
    ),

    path(
        "<int:pk>/delete/",
        ImpersonationDeleteView.as_view(),
        name="impersonation-delete",
    ),

    path(
        "<int:pk>/",
        ImpersonationDetailView.as_view(),
        name="impersonation-detail",
    ),
]