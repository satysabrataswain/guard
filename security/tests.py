from __future__ import annotations

from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase

from audit_logs.models import AuditLog


class APIAccessSecurityTests(APITestCase):
    """
    Regression tests for endpoint authorization and input handling.

    These tests intentionally use SQL-looking payloads as ordinary text.
    The application must treat them as data, not executable SQL.
    """

    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="security_test_user",
            user_id="security_test_user",
            email="security-test@example.com",
            phone_number="+919999999999",
            password="Strong-Test-Password-123!",
            first_name="Security",
            last_name="Test",
        )
        self.other_user = User.objects.create_user(
            username="security_test_other",
            user_id="security_test_other",
            email="security-other@example.com",
            phone_number="+918888888888",
            password="Strong-Test-Password-456!",
            first_name="Other",
            last_name="User",
        )

    def test_protected_api_endpoints_reject_anonymous_access(self):
        endpoints = [
            "/api/auth/me/",
            "/api/auth/logout/",
            "/api/threats/",
            "/api/threats/self-protection/ip-lookup/",
            "/api/phishing/history/",
            "/api/incidents/",
            "/api/audit/",
        ]

        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                self.assertIn(response.status_code, {401, 403})

    def test_audit_logs_are_not_writable_through_detail_endpoint(self):
        log = AuditLog.objects.create(
            user=self.user,
            action="LOGIN",
            ip_address="127.0.0.1",
            description="Immutable security event.",
            status="SUCCESS",
        )

        self.client.force_authenticate(user=self.user)

        update = self.client.patch(
            f"/api/audit/{log.id}/",
            {"description": "tampered"},
            format="json",
        )
        delete = self.client.delete(
            f"/api/audit/{log.id}/",
        )

        self.assertEqual(update.status_code, 405)
        self.assertEqual(delete.status_code, 405)

        log.refresh_from_db()
        self.assertEqual(
            log.description,
            "Immutable security event.",
        )

    def test_sql_like_search_is_treated_as_text(self):
        own_log = AuditLog.objects.create(
            user=self.user,
            action="LOGIN",
            ip_address="10.10.10.10",
            resource="login",
            description="Own security event.",
            status="SUCCESS",
        )
        AuditLog.objects.create(
            user=self.other_user,
            action="PASSWORD_RESET_REQUESTED",
            ip_address="10.10.10.11",
            resource="password-reset",
            description="Other user's event.",
            status="SUCCESS",
        )

        self.client.force_authenticate(user=self.user)

        payload = "' OR 1=1 --"
        response = self.client.get(
            "/api/audit/",
            {"search": payload},
        )

        self.assertEqual(response.status_code, 200)

        returned_ids = {
            item["id"]
            for item in response.data
        }
        self.assertNotIn(own_log.id, returned_ids)
        self.assertNotIn(
            next(
                log.id
                for log in AuditLog.objects.all()
                if log.user_id == self.other_user.id
            ),
            returned_ids,
        )

    def test_oversized_query_is_rejected_before_view(self):
        self.client.force_authenticate(user=self.user)

        response = self.client.get(
            "/api/audit/",
            {"search": "A" * 5000},
        )

        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertIn(
            "too long",
            str(payload.get("detail", "")).lower(),
        )


class BrowserPrivacySecurityTests(APITestCase):
    def setUp(self):
        import base64
        import os

        User = get_user_model()
        self.user = User.objects.create_user(
            username="browser_privacy_user",
            user_id="browser_privacy_user",
            email="browser-privacy@example.com",
            phone_number="+917777777777",
            password="Strong-Test-Password-789!",
            first_name="Browser",
            last_name="Privacy",
        )
        os.environ.setdefault(
            "DATA_ENCRYPTION_KEY",
            base64.urlsafe_b64encode(bytes(range(32))).decode("ascii"),
        )
        self.client.force_authenticate(user=self.user)

    def test_pair_connect_scan_and_history_flow(self):
        pair_response = self.client.post(
            "/api/browser-privacy/pair/",
            {},
            format="json",
        )
        self.assertEqual(pair_response.status_code, 201)

        code = pair_response.data["pairing_code"]

        self.client.force_authenticate(user=None)

        connect_response = self.client.post(
            "/api/browser-privacy/connect/",
            {"pairing_code": code},
            format="json",
        )
        self.assertEqual(connect_response.status_code, 200)

        scan_token = connect_response.data["scan_token"]

        scan_response = self.client.post(
            "/api/browser-privacy/scans/",
            {
                "browser": "Chrome/Chromium",
                "browser_version": "test",
                "platform": "Windows",
                "cookies": [
                    {
                        "name": "sessionid",
                        "domain": "example.com",
                        "path": "/",
                        "secure": True,
                        "httpOnly": True,
                        "sameSite": "Lax",
                        "value": "THIS_MUST_NEVER_BE_STORED",
                    }
                ],
                "extensions": [
                    {
                        "id": "a" * 32,
                        "name": "Test Extension",
                        "version": "1.0",
                        "enabled": True,
                        "permissions": ["cookies", "storage"],
                        "hostPermissions": ["<all_urls>"],
                    }
                ],
            },
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {scan_token}",
        )
        self.assertEqual(scan_response.status_code, 201)
        self.assertEqual(scan_response.data["summary"]["cookie_values_received"], False)

        self.client.force_authenticate(user=self.user)

        history_response = self.client.get("/api/browser-privacy/scans/history/")
        self.assertEqual(history_response.status_code, 200)
        self.assertEqual(history_response.data["count"], 1)

        stored_cookie = history_response.data["results"][0]["cookies"][0]
        self.assertNotIn("value", stored_cookie)
        self.assertEqual(stored_cookie["name"], "sessionid")
        self.assertEqual(
            history_response.data["results"][0]["high_impact_extension_count"],
            1,
        )

    def test_pairing_code_is_one_time_use(self):
        pair_response = self.client.post(
            "/api/browser-privacy/pair/",
            {},
            format="json",
        )
        self.assertEqual(pair_response.status_code, 201)

        code = pair_response.data["pairing_code"]

        self.client.force_authenticate(user=None)

        first = self.client.post(
            "/api/browser-privacy/connect/",
            {"pairing_code": code},
            format="json",
        )
        second = self.client.post(
            "/api/browser-privacy/connect/",
            {"pairing_code": code},
            format="json",
        )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 400)

    def test_browser_scan_token_cannot_access_user_history(self):
        self.client.force_authenticate(user=None)

        response = self.client.get(
            "/api/browser-privacy/scans/history/",
        )

        self.assertEqual(response.status_code, 401)
