from django.contrib.auth import get_user_model

from rest_framework import status
from rest_framework.test import APITestCase

from .models import Threat


User = get_user_model()


class ThreatDetectionTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username="THREATUSER001",
            user_id="THREATUSER001",
            first_name="Threat",
            last_name="Tester",
            email="threat@test.com",
            phone_number="9876543210",
            password="TestPassword123",
        )

        self.client.force_authenticate(
            user=self.user
        )

    def test_threat_list_requires_authentication(self):
        self.client.force_authenticate(
            user=None
        )

        response = self.client.get(
            "/api/threats/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED
        )

    def test_create_threat(self):
        data = {
            "threat_type": "PHISHING",
            "source_type": "URL",
            "input_data": "https://example-phishing.com/login",
        }

        response = self.client.post(
            "/api/threats/",
            data,
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED
        )

        self.assertEqual(
            Threat.objects.count(),
            1
        )

        threat = Threat.objects.first()

        self.assertEqual(
            threat.user,
            self.user
        )

        self.assertEqual(
            threat.threat_type,
            "PHISHING"
        )

    def test_threat_analyze(self):
        data = {
            "threat_type": "PHISHING",
            "source_type": "URL",
            "input_data": "https://suspicious-login.com",
        }

        response = self.client.post(
            "/api/threats/analyze/",
            data,
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED
        )

        self.assertEqual(
            response.data["message"],
            "Threat analysis completed."
        )

        self.assertEqual(
            Threat.objects.count(),
            1
        )

    def test_analyze_without_input_data(self):
        data = {
            "threat_type": "PHISHING",
            "source_type": "URL",
        }

        response = self.client.post(
            "/api/threats/analyze/",
            data,
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST
        )

    def test_invalid_threat_type(self):
        data = {
            "threat_type": "INVALID_TYPE",
            "source_type": "URL",
            "input_data": "https://example.com",
        }

        response = self.client.post(
            "/api/threats/analyze/",
            data,
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST
        )

    def test_get_threat_list(self):
        Threat.objects.create(
            user=self.user,
            threat_type="PHISHING",
            source_type="URL",
            input_data="https://example.com",
            risk_score=50,
            severity="MEDIUM",
            status="DETECTED",
            explanation="Test threat",
        )

        response = self.client.get(
            "/api/threats/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.assertEqual(
            len(response.data),
            1
        )

    def test_threat_detail(self):
        threat = Threat.objects.create(
            user=self.user,
            threat_type="MALICIOUS_URL",
            source_type="URL",
            input_data="https://malicious.com",
            risk_score=80,
            severity="CRITICAL",
            status="DETECTED",
            explanation="Malicious URL detected",
        )

        response = self.client.get(
            f"/api/threats/{threat.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK
        )

        self.assertEqual(
            response.data["id"],
            threat.id
        )

    def test_user_cannot_access_other_users_threat(self):
        other_user = User.objects.create_user(
            username="OTHERUSER001",
            user_id="OTHERUSER001",
            first_name="Other",
            last_name="User",
            email="other@test.com",
            phone_number="9123456780",
            password="TestPassword123",
        )

        threat = Threat.objects.create(
            user=other_user,
            threat_type="PHISHING",
            source_type="URL",
            input_data="https://other-user.com",
            risk_score=70,
            severity="HIGH",
            status="DETECTED",
        )

        response = self.client.get(
            f"/api/threats/{threat.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND
        )
