from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from typing import Any

import jwt
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.authentication import get_authorization_header
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from .authentication import BrowserPrivacyTokenAuthentication
from .models import BrowserPrivacyPairing, BrowserPrivacyScan


PAIRING_TTL_MINUTES = 10
SCAN_TOKEN_TTL_MINUTES = 30
MAX_COOKIE_ROWS = 250
MAX_EXTENSION_ROWS = 250


def _hash_pairing_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _make_scan_token(user_id: int) -> str:
    now = timezone.now()
    payload = {
        "sub": str(user_id),
        "purpose": "browser_privacy_scan",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=SCAN_TOKEN_TTL_MINUTES)).timestamp()),
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def _clean_text(value: Any, limit: int = 300) -> str:
    if value is None:
        return ""
    return str(value).strip()[:limit]


def _clean_cookie_metadata(rows: Any) -> list[dict]:
    if not isinstance(rows, list):
        return []

    cleaned = []

    for row in rows[:MAX_COOKIE_ROWS]:
        if not isinstance(row, dict):
            continue

        # Cookie values are intentionally discarded even if a malicious
        # client tries to submit them.
        name = _clean_text(row.get("name"), 200)
        domain = _clean_text(row.get("domain"), 255)
        path = _clean_text(row.get("path"), 300)
        same_site = _clean_text(row.get("sameSite"), 30)

        if not name:
            continue

        cleaned.append(
            {
                "name": name,
                "domain": domain,
                "path": path,
                "secure": bool(row.get("secure")),
                "http_only": bool(row.get("httpOnly")),
                "same_site": same_site,
                "host_only": bool(row.get("hostOnly")),
                "session": bool(row.get("session")),
            }
        )

    return cleaned


def _clean_extension_metadata(rows: Any) -> list[dict]:
    if not isinstance(rows, list):
        return []

    cleaned = []

    for row in rows[:MAX_EXTENSION_ROWS]:
        if not isinstance(row, dict):
            continue

        permissions = row.get("permissions")
        host_permissions = row.get("host_permissions")

        if not isinstance(permissions, list):
            permissions = []
        if not isinstance(host_permissions, list):
            host_permissions = []

        cleaned.append(
            {
                "id": _clean_text(row.get("id"), 128),
                "name": _clean_text(row.get("name"), 300),
                "version": _clean_text(row.get("version"), 100),
                "enabled": bool(row.get("enabled")),
                "type": _clean_text(row.get("type"), 50),
                "permissions": [
                    _clean_text(item, 150)
                    for item in permissions[:100]
                    if item is not None
                ],
                "host_permissions": [
                    _clean_text(item, 500)
                    for item in host_permissions[:100]
                    if item is not None
                ],
                "high_impact_permissions": [
                    _clean_text(item, 150)
                    for item in (row.get("high_impact_permissions") or [])[:100]
                    if item is not None
                ],
            }
        )

    return cleaned


class BrowserPrivacyPairView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "browser_privacy_pair"

    def post(self, request):
        code = secrets.token_hex(4).upper()
        expires_at = timezone.now() + timedelta(minutes=PAIRING_TTL_MINUTES)

        BrowserPrivacyPairing.objects.filter(
            user=request.user,
            used_at__isnull=True,
        ).delete()

        BrowserPrivacyPairing.objects.create(
            user=request.user,
            code_hash=_hash_pairing_code(code),
            expires_at=expires_at,
        )

        return Response(
            {
                "message": "Browser scanner pairing code created.",
                "pairing_code": code,
                "expires_at": expires_at,
                "expires_in_seconds": PAIRING_TTL_MINUTES * 60,
            },
            status=status.HTTP_201_CREATED,
        )


class BrowserPrivacyAutoTokenView(APIView):
    """Issue a short-lived scanner token to the already authenticated dashboard."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "browser_privacy_pair"

    def post(self, request):
        return Response(
            {
                "message": "Browser scanner auto-connection token created.",
                "scan_token": _make_scan_token(request.user.id),
                "expires_in_seconds": SCAN_TOKEN_TTL_MINUTES * 60,
            }
        )


class BrowserPrivacyConnectView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "browser_privacy_connect"

    def post(self, request):
        code = _clean_text(request.data.get("pairing_code"), 32).upper()

        if len(code) != 8:
            return Response(
                {"detail": "Enter the 8-character Cyber Guard pairing code."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        now = timezone.now()

        with transaction.atomic():
            pairing = (
                BrowserPrivacyPairing.objects.select_for_update()
                .filter(
                    code_hash=_hash_pairing_code(code),
                    used_at__isnull=True,
                    expires_at__gt=now,
                )
                .first()
            )

            if pairing is None:
                return Response(
                    {"detail": "Pairing code is invalid, expired, or already used."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            pairing.used_at = now
            pairing.save(update_fields=["used_at"])

        return Response(
            {
                "message": "Browser scanner connected.",
                "scan_token": _make_scan_token(pairing.user_id),
                "expires_in_seconds": SCAN_TOKEN_TTL_MINUTES * 60,
            }
        )


class BrowserPrivacyScanCreateView(APIView):
    authentication_classes = [BrowserPrivacyTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if not isinstance(request.data, dict):
            return Response(
                {"detail": "JSON object expected."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        cookies = _clean_cookie_metadata(request.data.get("cookies"))
        extensions = _clean_extension_metadata(request.data.get("extensions"))

        sensitive_cookie_count = sum(
            1
            for cookie in cookies
            if any(
                marker in cookie["name"].lower()
                for marker in (
                    "session",
                    "sess",
                    "auth",
                    "token",
                    "jwt",
                    "sid",
                    "csrf",
                    "xsrf",
                    "password",
                    "passwd",
                    "secret",
                    "access",
                    "refresh",
                )
            )
        )

        high_impact_extension_count = sum(
            1
            for extension in extensions
            if extension["high_impact_permissions"]
            or any(
                origin in {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
                for origin in extension["host_permissions"]
            )
        )

        summary = {
            "cookie_count": len(cookies),
            "sensitive_cookie_count": sensitive_cookie_count,
            "cookie_domains": len(
                {cookie["domain"] for cookie in cookies if cookie["domain"]}
            ),
            "extension_count": len(extensions),
            "enabled_extension_count": sum(
                1 for extension in extensions if extension["enabled"]
            ),
            "high_impact_extension_count": high_impact_extension_count,
            "metadata_only": True,
            "cookie_values_received": False,
            "declared_permissions_are_not_runtime_proof": True,
        }

        scan = BrowserPrivacyScan.objects.create(
            user=request.user,
            browser=_clean_text(request.data.get("browser"), 100),
            browser_version=_clean_text(request.data.get("browser_version"), 100),
            platform=_clean_text(request.data.get("platform"), 150),
            cookie_count=len(cookies),
            sensitive_cookie_count=sensitive_cookie_count,
            extension_count=len(extensions),
            high_impact_extension_count=high_impact_extension_count,
            cookie_metadata=cookies,
            extension_metadata=extensions,
            summary=summary,
        )

        return Response(
            {
                "message": "Browser privacy scan stored securely.",
                "scan_id": scan.id,
                "scanned_at": scan.scanned_at,
                "summary": summary,
            },
            status=status.HTTP_201_CREATED,
        )


class BrowserPrivacyDashboardScanCreateView(APIView):
    """Store a scan collected by the companion extension for the logged-in dashboard user."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "browser_privacy_connect"

    def post(self, request):
        if not isinstance(request.data, dict):
            return Response(
                {"detail": "JSON object expected."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        cookies = _clean_cookie_metadata(request.data.get("cookies"))
        extensions = _clean_extension_metadata(request.data.get("extensions"))

        sensitive_cookie_count = sum(
            1
            for cookie in cookies
            if any(
                marker in cookie["name"].lower()
                for marker in (
                    "session", "sess", "auth", "token", "jwt", "sid",
                    "csrf", "xsrf", "password", "passwd", "secret",
                    "access", "refresh",
                )
            )
        )
        high_impact_extension_count = sum(
            1
            for extension in extensions
            if extension["high_impact_permissions"]
            or any(
                origin in {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
                for origin in extension["host_permissions"]
            )
        )

        summary = {
            "cookie_count": len(cookies),
            "sensitive_cookie_count": sensitive_cookie_count,
            "cookie_domains": len({c["domain"] for c in cookies if c["domain"]}),
            "extension_count": len(extensions),
            "enabled_extension_count": sum(1 for e in extensions if e["enabled"]),
            "high_impact_extension_count": high_impact_extension_count,
            "metadata_only": True,
            "cookie_values_received": False,
            "declared_permissions_are_not_runtime_proof": True,
            "collection_mode": "automatic_companion_extension",
        }

        scan = BrowserPrivacyScan.objects.create(
            user=request.user,
            browser=_clean_text(request.data.get("browser"), 100),
            browser_version=_clean_text(request.data.get("browser_version"), 100),
            platform=_clean_text(request.data.get("platform"), 150),
            cookie_count=len(cookies),
            sensitive_cookie_count=sensitive_cookie_count,
            extension_count=len(extensions),
            high_impact_extension_count=high_impact_extension_count,
            cookie_metadata=cookies,
            extension_metadata=extensions,
            summary=summary,
        )

        return Response(
            {
                "message": "Automatic browser privacy scan stored.",
                "scan_id": scan.id,
                "scanned_at": scan.scanned_at,
                "summary": summary,
            },
            status=status.HTTP_201_CREATED,
        )


class BrowserPrivacyScanListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        scans = BrowserPrivacyScan.objects.filter(
            user=request.user
        )[:20]

        data = []

        for scan in scans:
            data.append(
                {
                    "id": scan.id,
                    "browser": scan.browser,
                    "browser_version": scan.browser_version,
                    "platform": scan.platform,
                    "cookie_count": scan.cookie_count,
                    "sensitive_cookie_count": scan.sensitive_cookie_count,
                    "extension_count": scan.extension_count,
                    "high_impact_extension_count": scan.high_impact_extension_count,
                    "cookies": scan.cookie_metadata,
                    "extensions": scan.extension_metadata,
                    "summary": scan.summary,
                    "scanned_at": scan.scanned_at,
                }
            )

        return Response(
            {
                "count": len(data),
                "results": data,
            }
        )
