from django.test import TestCase
from django.contrib.auth import get_user_model

User = get_user_model()


class UserModelTest(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username="TEST001",
            user_id="TEST001",
            first_name="Test",
            last_name="User",
            email="test@example.com",
            phone_number="9876543210",
            password="TestPassword123",
        )

    def test_user_created(self):
        self.assertEqual(self.user.user_id, "TEST001")
        self.assertEqual(self.user.role, "user")
        self.assertTrue(self.user.is_active)

    def test_password_is_hashed(self):
        self.assertNotEqual(
            self.user.password,
            "TestPassword123"
        )

    def test_user_login(self):
        self.assertTrue(
            self.user.check_password("TestPassword123")
        )