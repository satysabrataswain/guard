from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):

    ROLE_USER = "user"
    ROLE_ANALYST = "analyst"
    ROLE_ADMIN = "admin"

    ROLE_CHOICES = [
        (ROLE_USER, "User"),
        (ROLE_ANALYST, "Analyst"),
        (ROLE_ADMIN, "Admin"),
    ]

    user_id = models.CharField(
        max_length=50,
        unique=True
    )

    first_name = models.CharField(
        max_length=100
    )

    last_name = models.CharField(
        max_length=100
    )

    email = models.EmailField(
        unique=True
    )

    phone_number = models.CharField(
        max_length=15,
        unique=True
    )

    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default=ROLE_USER
    )

    is_active = models.BooleanField(
        default=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        auto_now=True
    )

    def __str__(self):
        return f"{self.user_id} - {self.email}"