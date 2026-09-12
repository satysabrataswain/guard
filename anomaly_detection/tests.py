from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from .models import (
    Anomaly,
    LoginActivity,
    UserBehaviour,
)


User = get_user_model()


class AnomalyDetectionTests(APITestCase):

    def setUp(self):

        self.user = User.objects.create_user(
            username="ANOM001",
            user_id="ANOM001",
            first_name="Anomaly",
            last_name="User",
            email="anomaly@example.com",
            phone_number="9876543210",
            password="TestPassword123",
        )

        self.other_user = User.objects.create_user(
            username="ANOM002",
            user_id="ANOM002",
            first_name="Other",
            last_name="User",
            email="other@example.com",
            phone_number="9876543211",
            password="TestPassword123",
        )

        refresh = RefreshToken.for_user(
            self.user
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}"
        )

    def test_login_analysis(self):

        response = self.client.post(
            "/api/anomaly/login/analyze/",
            {
                "ip_address": "192.168.1.10",
                "device_id": "device-001",
                "location": "Bhubaneswar",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            201,
            response.data,
        )

        self.assertEqual(
            Anomaly.objects.count(),
            1,
        )

        self.assertEqual(
            LoginActivity.objects.count(),
            1,
        )

    def test_behaviour_creation(self):

        response = self.client.post(
            "/api/anomaly/behavior/",
            {
                "activity_type": "ACCESS",
                "ip_address": "192.168.1.20",
                "location": "Bhubaneswar",
                "device_id": "device-002",
                "activity_data": {
                    "resource": "/dashboard"
                },
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            201,
            response.data,
        )

        self.assertEqual(
            UserBehaviour.objects.count(),
            1,
        )

    def test_login_activity_creation(self):

        response = self.client.post(
            "/api/anomaly/login/activity/",
            {
                "ip_address": "10.0.0.10",
                "location": "Cuttack",
                "device_id": "device-003",
                "status": "SUCCESS",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            201,
            response.data,
        )

        self.assertEqual(
            LoginActivity.objects.count(),
            1,
        )

    def test_anomaly_history(self):

        Anomaly.objects.create(
            user=self.user,
            anomaly_type="LOGIN_BEHAVIOUR",
            risk_score=45,
            severity="MEDIUM",
            explanation="Test anomaly",
        )

        response = self.client.get(
            "/api/anomaly/history/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            len(response.data),
            1,
        )

    def test_anomaly_detail(self):

        anomaly = Anomaly.objects.create(
            user=self.user,
            anomaly_type="ACCOUNT_TAKEOVER",
            risk_score=75,
            severity="HIGH",
            explanation="Suspicious login",
        )

        response = self.client.get(
            f"/api/anomaly/{anomaly.id}/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.data["risk_score"],
            75,
        )

    def test_user_cannot_access_other_user_anomaly(self):

        anomaly = Anomaly.objects.create(
            user=self.other_user,
            anomaly_type="LOGIN_BEHAVIOUR",
            risk_score=80,
            severity="CRITICAL",
            explanation="Other user anomaly",
        )

        response = self.client.get(
            f"/api/anomaly/{anomaly.id}/"
        )

        self.assertEqual(
            response.status_code,
            404,
        )

    def test_behaviour_history(self):

        UserBehaviour.objects.create(
            user=self.user,
            activity_type="DEVICE",
            ip_address="10.0.0.1",
        )

        response = self.client.get(
            "/api/anomaly/behavior/history/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            len(response.data),
            1,
        )

    def test_login_history(self):

        LoginActivity.objects.create(
            user=self.user,
            ip_address="10.0.0.2",
            status="SUCCESS",
        )

        response = self.client.get(
            "/api/anomaly/login/history/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            len(response.data),
            1,
        )

    def test_requires_authentication(self):

        self.client.credentials()

        response = self.client.get(
            "/api/anomaly/history/"
        )

        self.assertEqual(
            response.status_code,
            401,
        )

    def test_severe_login_anomaly(self):

        for i in range(5):

            LoginActivity.objects.create(
                user=self.user,
                ip_address=f"10.0.0.{i}",
                status="FAILED",
            )

        response = self.client.post(
            "/api/anomaly/login/analyze/",
            {
                "ip_address": "172.16.0.10",
                "device_id": "new-device",
                "location": "Unknown",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            201,
            response.data,
        )

        self.assertGreaterEqual(
            response.data["anomaly"]["risk_score"],
            60,
        )