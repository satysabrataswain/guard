from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile

from rest_framework import status
from rest_framework.test import APITestCase

from .models import (
    ImpersonationScan,
    DeepfakeAnalysis,
    IdentityAnalysis,
    ImpersonationEvidence,
)


User = get_user_model()


class ImpersonationTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username="IMPERSONATION001",
            user_id="IMPERSONATION001",
            first_name="Impersonation",
            last_name="Tester",
            email="impersonation@test.com",
            phone_number="9876543210",
            password="TestPassword123",
        )

        self.client.force_authenticate(
            user=self.user
        )

    def test_image_analysis(self):
        image_file = SimpleUploadedFile(
            "test.jpg",
            b"fake-image-content",
            content_type="image/jpeg",
        )

        response = self.client.post(
            "/api/impersonation/image/analyze/",
            {
                "image": image_file,
            },
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
            response.data,
        )

        self.assertEqual(
            ImpersonationScan.objects.count(),
            1,
        )

        self.assertEqual(
            DeepfakeAnalysis.objects.count(),
            1,
        )

        self.assertEqual(
            IdentityAnalysis.objects.count(),
            1,
        )

        self.assertEqual(
            ImpersonationEvidence.objects.count(),
            1,
        )

        scan = ImpersonationScan.objects.first()

        self.assertEqual(
            scan.user,
            self.user,
        )

        self.assertEqual(
            scan.scan_type,
            "IMAGE",
        )

    def test_video_analysis(self):
        video_file = SimpleUploadedFile(
            "test.mp4",
            b"fake-video-content",
            content_type="video/mp4",
        )

        response = self.client.post(
            "/api/impersonation/video/analyze/",
            {
                "video": video_file,
            },
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
            response.data,
        )

        self.assertEqual(
            ImpersonationScan.objects.count(),
            1,
        )

        scan = ImpersonationScan.objects.first()

        self.assertEqual(
            scan.user,
            self.user,
        )

        self.assertEqual(
            scan.scan_type,
            "VIDEO",
        )

        self.assertEqual(
            DeepfakeAnalysis.objects.count(),
            1,
        )

        self.assertEqual(
            IdentityAnalysis.objects.count(),
            1,
        )

        self.assertEqual(
            ImpersonationEvidence.objects.count(),
            1,
        )

    def test_image_required(self):
        response = self.client.post(
            "/api/impersonation/image/analyze/",
            {},
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_video_required(self):
        response = self.client.post(
            "/api/impersonation/video/analyze/",
            {},
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_invalid_image_extension(self):
        image_file = SimpleUploadedFile(
            "test.txt",
            b"invalid",
            content_type="text/plain",
        )

        response = self.client.post(
            "/api/impersonation/image/analyze/",
            {
                "image": image_file,
            },
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_invalid_video_extension(self):
        video_file = SimpleUploadedFile(
            "test.txt",
            b"invalid",
            content_type="text/plain",
        )

        response = self.client.post(
            "/api/impersonation/video/analyze/",
            {
                "video": video_file,
            },
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_history(self):
        ImpersonationScan.objects.create(
            user=self.user,
            scan_type="IMAGE",
            file_name="history.jpg",
            file_size=100,
            risk_score=10,
            result="SAFE",
            explanation="Test scan",
            status="COMPLETED",
        )

        response = self.client.get(
            "/api/impersonation/history/"
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
        scan = ImpersonationScan.objects.create(
            user=self.user,
            scan_type="IMAGE",
            file_name="detail.jpg",
            file_size=100,
            risk_score=20,
            result="LOW",
            status="COMPLETED",
        )

        response = self.client.get(
            f"/api/impersonation/{scan.id}/"
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
            username="OTHERIMPERSONATION",
            user_id="OTHERIMPERSONATION",
            first_name="Other",
            last_name="User",
            email="otherimpersonation@test.com",
            phone_number="9123456780",
            password="TestPassword123",
        )

        scan = ImpersonationScan.objects.create(
            user=other_user,
            scan_type="IMAGE",
            file_name="private.jpg",
            file_size=100,
            risk_score=80,
            result="CRITICAL",
            status="COMPLETED",
        )

        response = self.client.get(
            f"/api/impersonation/{scan.id}/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
        )

    def test_delete_scan(self):
        scan = ImpersonationScan.objects.create(
            user=self.user,
            scan_type="IMAGE",
            file_name="delete.jpg",
            file_size=100,
            risk_score=10,
            result="SAFE",
            status="COMPLETED",
        )

        response = self.client.delete(
            f"/api/impersonation/{scan.id}/delete/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_204_NO_CONTENT,
        )

        self.assertEqual(
            ImpersonationScan.objects.count(),
            0,
        )

    def test_requires_authentication(self):
        self.client.force_authenticate(
            user=None
        )

        response = self.client.get(
            "/api/impersonation/history/"
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )
