from django.urls import path

from .views import (
    AnalyseLoginView,
    BehaviourCreateView,
    LoginActivityCreateView,
    AnomalyHistoryView,
    AnomalyDetailView,
    BehaviourHistoryView,
    LoginHistoryView,
)


urlpatterns = [

    path(
        "login/analyze/",
        AnalyseLoginView.as_view(),
        name="login-analyze",
    ),

    path(
        "behavior/",
        BehaviourCreateView.as_view(),
        name="behavior-create",
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
        "login/history/",
        LoginHistoryView.as_view(),
        name="login-history",
    ),

    path(
        "<int:pk>/",
        AnomalyDetailView.as_view(),
        name="anomaly-detail",
    ),
]