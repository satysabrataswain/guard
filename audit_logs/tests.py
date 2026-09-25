from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from .models import AuditLog


User = get_user_model()


class AuditLogTests(APITestCase):

    def setUp(self):

        self.user = User.objects.create_user(
            username="AUD001",
            user_id="AUD001",
            first_name="Audit",
            last_name="User",
            email="audit@example.com",
            phone_number="9876543100",
            password="TestPassword123",
        )

        self.other_user = User.objects.create_user(
            username="AUD002",
            user_id="AUD002",
            first_name="Other",
            last_name="User",
            email="other@example.com",
            phone_number="9876543101",
            password="TestPassword123",
        )

        self.admin = User.objects.create_user(
            username="ADMIN001",
            user_id="ADMIN001",
            first_name="Admin",
            last_name="User",
            email="admin@example.com",
            phone_number="9876543102",
            password="AdminPassword123",
            role="admin",
        )

        refresh = RefreshToken.for_user(self.user)

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {refresh.access_token}"
            )
        )

    def test_user_can_view_own_logs(self):

        AuditLog.objects.create(
            user=self.user,
            action="LOGIN",
            ip_address="192.168.1.10",
            user_agent="Test Browser",
            description="Successful login",
            status="SUCCESS",
        )

        response = self.client.get(
            "/api/audit/my/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            len(response.data),
            1,
        )

        self.assertEqual(
            response.data[0]["action"],
            "LOGIN",
        )

    def test_user_cannot_view_other_user_logs(self):

        AuditLog.objects.create(
            user=self.other_user,
            action="LOGIN",
            ip_address="10.0.0.10",
            description="Other user login",
        )

        response = self.client.get(
            "/api/audit/my/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            len(response.data),
            0,
        )

    def test_admin_can_view_all_logs(self):

        AuditLog.objects.create(
            user=self.user,
            action="LOGIN",
            description="User login",
        )

        AuditLog.objects.create(
            user=self.other_user,
            action="FAILED_LOGIN",
            description="Failed login",
            status="FAILED",
        )

        refresh = RefreshToken.for_user(
            self.admin
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {refresh.access_token}"
            )
        )

        response = self.client.get(
            "/api/audit/admin/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            len(response.data),
            2,
        )

    def test_normal_user_cannot_view_admin_logs(self):

        response = self.client.get(
            "/api/audit/admin/"
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_unauthenticated_user_cannot_view_logs(self):

        self.client.credentials()

        response = self.client.get(
            "/api/audit/my/"
        )

        self.assertEqual(
            response.status_code,
            401,
        )

    def test_audit_log_stores_ip_and_user_agent(self):

        log = AuditLog.objects.create(
            user=self.user,
            action="LOGIN",
            ip_address="127.0.0.1",
            user_agent="Chrome Test",
        )

        self.assertEqual(
            log.ip_address,
            "127.0.0.1",
        )

        self.assertEqual(
            log.user_agent,
            "Chrome Test",
        )

    def test_audit_log_actions(self):

        actions = [
            "LOGIN",
            "FAILED_LOGIN",
            "LOGOUT",
            "REGISTER",
            "THREAT_ANALYZED",
            "PHISHING_SCAN",
            "IMPERSONATION_DETECTED",
            "DEEPFAKE_DETECTED",
            "ANOMALY_DETECTED",
            "INCIDENT_CREATED",
            "INCIDENT_UPDATED",
            "INCIDENT_RESOLVED",
        ]

        for action in actions:
            AuditLog.objects.create(
                user=self.user,
                action=action,
            )

        self.assertEqual(
            AuditLog.objects.count(),
            len(actions),
        )

    def test_audit_log_ordering(self):

        first = AuditLog.objects.create(
            user=self.user,
            action="LOGIN",
        )

        second = AuditLog.objects.create(
            user=self.user,
            action="LOGOUT",
        )

        logs = AuditLog.objects.all()

        self.assertEqual(
            logs.first().id,
            second.id,
        )

        self.assertEqual(
            logs.last().id,
            first.id,
        )

    def test_system_log_without_user(self):

        log = AuditLog.objects.create(
            user=None,
            action="FAILED_LOGIN",
            status="FAILED",
            description="Unknown login attempt",
        )

        self.assertIsNone(
            log.user
        )

        self.assertEqual(
            log.action,
            "FAILED_LOGIN",
        )

    def test_admin_log_endpoint_requires_admin_role(self):

        normal_user = self.user

        AuditLog.objects.create(
            user=normal_user,
            action="LOGIN",
        )

        response = self.client.get(
            "/api/audit/admin/"
        )

        self.assertEqual(
            response.status_code,
            403,
        )