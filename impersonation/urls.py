from django.urls import path

from .views import (
    ImpersonationHistoryView,
    ImpersonationDetailView,
    ImpersonationDeleteView,
    ImageAnalyzeView,
    VideoAnalyzeView,
    VoiceAnalyzeView,
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
        "voice/analyze/",
        VoiceAnalyzeView.as_view(),
        name="voice-analyze",
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