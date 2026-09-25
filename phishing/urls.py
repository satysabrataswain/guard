from django.urls import path

from .views import (
    PhishingScanListCreateView,
    PhishingScanDetailView,
    PhishingScanDeleteView,
    URLAnalysisView,
    EmailAnalysisView,
    EmailScreenshotOCRView,
)


urlpatterns = [
    path(
        "url/analyze/",
        URLAnalysisView.as_view(),
        name="url-analyze",
    ),

    path(
        "email/analyze/",
        EmailAnalysisView.as_view(),
        name="email-analyze",
    ),

    path(
        "email/ocr/",
        EmailScreenshotOCRView.as_view(),
        name="email-screenshot-ocr",
    ),

    path(
        "history/",
        PhishingScanListCreateView.as_view(),
        name="phishing-history",
    ),

    path(
        "<int:pk>/delete/",
        PhishingScanDeleteView.as_view(),
        name="phishing-delete",
    ),

    path(
        "<int:pk>/",
        PhishingScanDetailView.as_view(),
        name="phishing-detail",
    ),
]