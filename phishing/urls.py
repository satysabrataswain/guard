from django.urls import path

from .views import (
    PhishingScanListView,
    PhishingScanDetailView,
    URLAnalyzeView,
    EmailAnalyzeView,
    PhishingScanDeleteView,
)


urlpatterns = [

    path(
        "url/analyze/",
        URLAnalyzeView.as_view(),
        name="url-analyze",
    ),

    path(
        "email/analyze/",
        EmailAnalyzeView.as_view(),
        name="email-analyze",
    ),

    path(
        "history/",
        PhishingScanListView.as_view(),
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