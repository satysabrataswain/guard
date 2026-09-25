from django.urls import path

from .views import (
    BrowserPrivacyConnectView,
    BrowserPrivacyAutoTokenView,
    BrowserPrivacyPairView,
    BrowserPrivacyScanCreateView,
    BrowserPrivacyDashboardScanCreateView,
    BrowserPrivacyScanListView,
)

urlpatterns = [
    path("auto-token/", BrowserPrivacyAutoTokenView.as_view(), name="browser-privacy-auto-token"),
    path("pair/", BrowserPrivacyPairView.as_view(), name="browser-privacy-pair"),
    path("connect/", BrowserPrivacyConnectView.as_view(), name="browser-privacy-connect"),
    path("scans/", BrowserPrivacyScanCreateView.as_view(), name="browser-privacy-scan-create"),
    path("scans/dashboard/", BrowserPrivacyDashboardScanCreateView.as_view(), name="browser-privacy-dashboard-scan-create"),
    path("scans/history/", BrowserPrivacyScanListView.as_view(), name="browser-privacy-scan-history"),
]
