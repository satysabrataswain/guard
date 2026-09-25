from django.contrib.auth import get_user_model

from rest_framework import status
from rest_framework.test import APITestCase

from .models import (
    PhishingScan,
    URLAnalysis,
    EmailAnalysis,
)


User = get_user_model()


class PhishingTests(APITestCase):

    def setUp(self):

        self.user = User.objects.create_user(
            username="PHISHUSER001",
            user_id="PHISHUSER001",
            first_name="Phishing",
            last_name="Tester",
            email="phishing@test.com",
            phone_number="9876543210",
            password="TestPassword123",
        )

        self.client.force_authenticate(
            user=self.user
        )

    def test_url_analysis(self):

        data = {
            "url":
            "https://example.com/login"
        }

        response = self.client.post(
            "/api/phishing/url/analyze/",
            data,
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        self.assertEqual(
            PhishingScan.objects.count(),
            1,
        )

        self.assertEqual(
            URLAnalysis.objects.count(),
            1,
        )

        scan = PhishingScan.objects.first()

        self.assertEqual(
            scan.user,
            self.user,
        )

        self.assertEqual(
            scan.scan_type,
            "URL",
        )

    def test_invalid_url(self):

        data = {
            "url": "not-a-valid-url"
        }

        response = self.client.post(
            "/api/phishing/url/analyze/",
            data,
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_url_without_data(self):

        response = self.client.post(
            "/api/phishing/url/analyze/",
            {},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_suspicious_url(self):

        data = {
            "url":
            "http://192.168.1.10/login/verify/account"
        }

        response = self.client.post(
            "/api/phishing/url/analyze/",
            data,
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        scan = PhishingScan.objects.first()

        self.assertGreater(
            scan.risk_score,
            0,
        )

        self.assertIn(
            scan.result,
            [
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            ],
        )

    def test_email_analysis(self):

        data = {
            "sender":
            "security@example.com",

            "subject":
            "Urgent account verification required",

            "body":
            "Please login immediately and verify your account.",
        }

        response = self.client.post(
            "/api/phishing/email/analyze/",
            data,
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        self.assertEqual(
            PhishingScan.objects.count(),
            1,
        )

        self.assertEqual(
            EmailAnalysis.objects.count(),
            1,
        )

        scan = PhishingScan.objects.first()

        self.assertEqual(
            scan.scan_type,
            "EMAIL",
        )

    def test_email_without_content(self):

        data = {
            "sender":
            "security@example.com"
        }

        response = self.client.post(
            "/api/phishing/email/analyze/",
            data,
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_invalid_sender_email(self):

        data = {
            "sender": "invalid-email",
            "subject": "Test",
            "body": "Test email",
        }

        response = self.client.post(
            "/api/phishing/email/analyze/",
            data,
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_phishing_history(self):

        PhishingScan.objects.create(
            user=self.user,
            scan_type="URL",
            input_data="https://example.com",
            risk_score=20,
            result="LOW",
            explanation="Test scan",
            status="COMPLETED",
        )

        response = self.client.get(
            "/api/phishing/history/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertEqual(
            len(response.data),
            1,
        )

    def test_scan_detail(self):

        scan = PhishingScan.objects.create(
            user=self.user,
            scan_type="URL",
            input_data="https://example.com",
            risk_score=10,
            result="SAFE",
            explanation="Safe",
            status="COMPLETED",
        )

        response = self.client.get(
            f"/api/phishing/{scan.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertEqual(
            response.data["id"],
            scan.id,
        )

    def test_user_cannot_access_other_user_scan(self):

        other_user = User.objects.create_user(
            username="OTHERPHISH001",
            user_id="OTHERPHISH001",
            first_name="Other",
            last_name="User",
            email="otherphish@test.com",
            phone_number="9123456780",
            password="TestPassword123",
        )

        scan = PhishingScan.objects.create(
            user=other_user,
            scan_type="URL",
            input_data="https://other.com",
            risk_score=80,
            result="CRITICAL",
            status="COMPLETED",
        )

        response = self.client.get(
            f"/api/phishing/{scan.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
        )

    def test_phishing_delete(self):

        scan = PhishingScan.objects.create(
            user=self.user,
            scan_type="URL",
            input_data="https://example.com",
            risk_score=10,
            result="SAFE",
            status="COMPLETED",
        )

        response = self.client.delete(
            f"/api/phishing/{scan.id}/delete/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_204_NO_CONTENT,
        )

        self.assertEqual(
            PhishingScan.objects.count(),
            0,
        )

    def test_phishing_requires_authentication(self):

        self.client.force_authenticate(
            user=None
        )

        response = self.client.get(
            "/api/phishing/history/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )