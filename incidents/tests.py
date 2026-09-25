from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from .models import (
    Incident,
    IncidentEvidence,
    ResponseAction,
)


User = get_user_model()


class IncidentTests(APITestCase):

    def setUp(self):

        self.user = User.objects.create_user(
            username="INC001",
            user_id="INC001",
            first_name="Incident",
            last_name="User",
            email="incident@example.com",
            phone_number="9876543200",
            password="TestPassword123",
        )

        self.other_user = User.objects.create_user(
            username="INC002",
            user_id="INC002",
            first_name="Other",
            last_name="User",
            email="other@example.com",
            phone_number="9876543201",
            password="TestPassword123",
        )

        refresh = RefreshToken.for_user(
            self.user
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=(
                f"Bearer {refresh.access_token}"
            )
        )

    def test_create_incident(self):

        response = self.client.post(
            "/api/incidents/",
            {
                "incident_type": "PHISHING",
                "title": "Suspicious phishing attack",
                "description": "Phishing URL detected",
                "severity": "HIGH",
                "risk_score": 75,
                "source_type": "PHISHING",
                "source_id": 1,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            201,
            response.data,
        )

        self.assertEqual(
            Incident.objects.count(),
            1,
        )

    def test_incident_history(self):

        Incident.objects.create(
            incident_type="MALICIOUS_URL",
            title="Malicious URL",
            description="Test incident",
            severity="HIGH",
            risk_score=70,
            created_by=self.user,
        )

        response = self.client.get(
            "/api/incidents/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            len(response.data),
            1,
        )

    def test_incident_detail(self):

        incident = Incident.objects.create(
            incident_type="DEEPFAKE",
            title="Deepfake detected",
            severity="CRITICAL",
            risk_score=90,
            created_by=self.user,
        )

        response = self.client.get(
            f"/api/incidents/{incident.id}/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.data["risk_score"],
            90,
        )

    def test_update_incident(self):

        incident = Incident.objects.create(
            incident_type="ANOMALY",
            title="Suspicious behaviour",
            severity="MEDIUM",
            risk_score=50,
            created_by=self.user,
        )

        response = self.client.patch(
            f"/api/incidents/{incident.id}/",
            {
                "status": "INVESTIGATING",
                "severity": "HIGH",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        incident.refresh_from_db()

        self.assertEqual(
            incident.status,
            "INVESTIGATING",
        )

        self.assertEqual(
            incident.severity,
            "HIGH",
        )

    def test_user_cannot_access_other_user_incident(self):

        incident = Incident.objects.create(
            incident_type="ACCOUNT_TAKEOVER",
            title="Other user incident",
            severity="CRITICAL",
            risk_score=95,
            created_by=self.other_user,
        )

        response = self.client.get(
            f"/api/incidents/{incident.id}/"
        )

        self.assertEqual(
            response.status_code,
            404,
        )

    def test_add_evidence(self):

        incident = Incident.objects.create(
            incident_type="PHISHING",
            title="Phishing incident",
            severity="HIGH",
            risk_score=70,
            created_by=self.user,
        )

        response = self.client.post(
            f"/api/incidents/{incident.id}/evidence/",
            {
                "evidence_type": "SUSPICIOUS_URL",
                "evidence_value": (
                    "https://example.com/login"
                ),
                "risk_contribution": 30,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            201,
            response.data,
        )

        self.assertEqual(
            IncidentEvidence.objects.count(),
            1,
        )

    def test_create_response_action(self):

        incident = Incident.objects.create(
            incident_type="MALICIOUS_URL",
            title="Malicious website",
            severity="HIGH",
            risk_score=80,
            created_by=self.user,
        )

        response = self.client.post(
            f"/api/incidents/{incident.id}/response/",
            {
                "action_type": "BLOCK_URL",
                "description": (
                    "Block detected malicious URL"
                ),
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            201,
            response.data,
        )

        self.assertEqual(
            ResponseAction.objects.count(),
            1,
        )

    def test_execute_response_action(self):

        incident = Incident.objects.create(
            incident_type="PHISHING",
            title="Phishing attack",
            severity="HIGH",
            risk_score=75,
            created_by=self.user,
        )

        action = ResponseAction.objects.create(
            incident=incident,
            action_type="ALERT_USER",
            description="Alert affected user",
        )

        response = self.client.post(
            f"/api/incidents/response/"
            f"{action.id}/execute/",
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        action.refresh_from_db()

        self.assertEqual(
            action.status,
            "EXECUTED",
        )

        self.assertEqual(
            action.executed_by,
            self.user,
        )

        self.assertIsNotNone(
            action.executed_at
        )

    def test_resolve_incident(self):

        incident = Incident.objects.create(
            incident_type="ANOMALY",
            title="Suspicious login",
            severity="MEDIUM",
            risk_score=55,
            created_by=self.user,
        )

        response = self.client.post(
            f"/api/incidents/{incident.id}/resolve/",
            format="json",
        )

        self.assertEqual(
            response.status_code,
            200,
            response.data,
        )

        incident.refresh_from_db()

        self.assertEqual(
            incident.status,
            "RESOLVED",
        )

        self.assertIsNotNone(
            incident.resolved_at
        )

    def test_delete_incident(self):

        incident = Incident.objects.create(
            incident_type="OTHER",
            title="Test incident",
            severity="LOW",
            risk_score=20,
            created_by=self.user,
        )

        response = self.client.delete(
            f"/api/incidents/{incident.id}/delete/"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertFalse(
            Incident.objects.filter(
                id=incident.id
            ).exists()
        )

    def test_requires_authentication(self):

        self.client.credentials()

        response = self.client.get(
            "/api/incidents/"
        )

        self.assertEqual(
            response.status_code,
            401,
        )