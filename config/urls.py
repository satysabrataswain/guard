from __future__ import annotations

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path


urlpatterns = [


    path(
        "admin/",
        admin.site.urls,
    ),


    path(
        "api/auth/",
        include("accounts.urls"),
    ),


    path(
        "api/threats/",
        include("threat_detection.urls"),
    ),


    path(
        "api/phishing/",
        include("phishing.urls"),
    ),

    

    path(
        "api/impersonation/",
        include("impersonation.urls"),
    ),

   
    path(
        "api/anomaly/",
        include("anomaly_detection.urls"),
    ),


    path(
        "api/incidents/",
        include("incidents.urls"),
    ),


    path(
        "api/audit/",
        include("audit_logs.urls"),
    ),
]


# ============================================================
# DEVELOPMENT MEDIA SERVING
# ============================================================

# Serve uploaded media through Django only during local
# development.
#
# In production, serve media through Nginx, object storage,
# CDN, or another dedicated media server.

if settings.DEBUG:

    urlpatterns += static(
        settings.MEDIA_URL,
        document_root=settings.MEDIA_ROOT,
    )
