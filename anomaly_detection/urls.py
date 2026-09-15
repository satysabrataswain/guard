from django.urls import path

from .views import (
    LoginAnalysisView,
    BehaviourAnalysisView,
    LoginActivityCreateView,
    LoginActivityHistoryView,
    LoginActivityDetailView,
    BehaviourHistoryView,
    BehaviourDetailView,
    AnomalyHistoryView,
    AnomalyDetailView,
)


urlpatterns = [
    path(
        "login/analyze/",
        LoginAnalysisView.as_view(),
        name="login-analyze",
    ),

    path(
        "behavior/",
        BehaviourAnalysisView.as_view(),
        name="behavior-analyze",
    ),

    path(
        "login/activity/",
        LoginActivityCreateView.as_view(),
        name="login-activity",
    ),

    path(
        "history/",
        AnomalyHistoryView.as_view(),
        name="anomaly-history",
    ),

    path(
        "behavior/history/",
        BehaviourHistoryView.as_view(),
        name="behavior-history",
    ),

    path(
        "behavior/<int:pk>/",
        BehaviourDetailView.as_view(),
        name="behavior-detail",
    ),

    path(
        "login/history/",
        LoginActivityHistoryView.as_view(),
        name="login-history",
    ),

    path(
        "login/activity/<int:pk>/",
        LoginActivityDetailView.as_view(),
        name="login-activity-detail",
    ),

    path(
        "<int:pk>/",
        AnomalyDetailView.as_view(),
        name="anomaly-detail",
    ),
]