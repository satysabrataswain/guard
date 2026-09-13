from __future__ import annotations

import re

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import (
    validate_password,
)
from django.core.exceptions import (
    ValidationError as DjangoValidationError,
)

from rest_framework import serializers


User = get_user_model()


# --------------------------------------------------
# VALIDATION CONFIGURATION
# --------------------------------------------------

MIN_PASSWORD_LENGTH = 12

MAX_USER_ID_LENGTH = 50

PHONE_PATTERN = re.compile(
    r"^\+?[0-9]{10,15}$"
)


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def _normalize_email(
    value: str,
) -> str:
    return str(
        value or ""
    ).strip().lower()


def _normalize_user_id(
    value: str,
) -> str:
    return str(
        value or ""
    ).strip()


def _normalize_phone(
    value: str,
) -> str:
    phone = str(
        value or ""
    ).strip()

    # Remove common formatting characters.
    phone = re.sub(
        r"[\s\-\(\)]",
        "",
        phone,
    )

    return phone


# --------------------------------------------------
# REGISTER SERIALIZER
# --------------------------------------------------

class RegisterSerializer(
    serializers.ModelSerializer
):

    password = serializers.CharField(
        write_only=True,
        min_length=MIN_PASSWORD_LENGTH,
        max_length=128,
        trim_whitespace=False,
        style={
            "input_type": "password"
        },
    )

    password_confirm = serializers.CharField(
        write_only=True,
        min_length=MIN_PASSWORD_LENGTH,
        max_length=128,
        trim_whitespace=False,
        style={
            "input_type": "password"
        },
    )

    class Meta:

        model = User

        fields = [
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "user_id",
            "password",
            "password_confirm",
        ]

        extra_kwargs = {
            "first_name": {
                "required": True,
                "allow_blank": False,
                "max_length": 100,
            },
            "last_name": {
                "required": True,
                "allow_blank": False,
                "max_length": 100,
            },
            "email": {
                "required": True,
                "allow_blank": False,
            },
            "phone_number": {
                "required": True,
                "allow_blank": False,
            },
            "user_id": {
                "required": True,
                "allow_blank": False,
                "max_length": MAX_USER_ID_LENGTH,
            },
        }

    # --------------------------------------------------
    # FIELD VALIDATION
    # --------------------------------------------------

    def validate_first_name(
        self,
        value,
    ):
        value = str(
            value or ""
        ).strip()

        if not value:
            raise serializers.ValidationError(
                "First name is required."
            )

        if len(value) < 2:
            raise serializers.ValidationError(
                "First name must contain at least 2 characters."
            )

        if len(value) > 100:
            raise serializers.ValidationError(
                "First name cannot exceed 100 characters."
            )

        return value

    def validate_last_name(
        self,
        value,
    ):
        value = str(
            value or ""
        ).strip()

        if not value:
            raise serializers.ValidationError(
                "Last name is required."
            )

        if len(value) < 2:
            raise serializers.ValidationError(
                "Last name must contain at least 2 characters."
            )

        if len(value) > 100:
            raise serializers.ValidationError(
                "Last name cannot exceed 100 characters."
            )

        return value

    def validate_email(
        self,
        value,
    ):
        email = _normalize_email(
            value
        )

        if not email:
            raise serializers.ValidationError(
                "Email address is required."
            )

        # Model-level uniqueness is also enforced,
        # but checking here gives a clean API error.
        if User.objects.filter(
            email__iexact=email
        ).exists():
            raise serializers.ValidationError(
                "An account with this email already exists."
            )

        return email

    def validate_phone_number(
        self,
        value,
    ):
        phone = _normalize_phone(
            value
        )

        if not phone:
            raise serializers.ValidationError(
                "Phone number is required."
            )

        if not PHONE_PATTERN.fullmatch(
            phone
        ):
            raise serializers.ValidationError(
                (
                    "Enter a valid phone number "
                    "containing 10 to 15 digits, "
                    "optionally prefixed with '+'."
                )
            )

        if User.objects.filter(
            phone_number=phone
        ).exists():
            raise serializers.ValidationError(
                "An account with this phone number already exists."
            )

        return phone

    def validate_user_id(
        self,
        value,
    ):
        user_id = _normalize_user_id(
            value
        )

        if not user_id:
            raise serializers.ValidationError(
                "User ID is required."
            )

        if len(user_id) < 4:
            raise serializers.ValidationError(
                "User ID must contain at least 4 characters."
            )

        if len(user_id) > MAX_USER_ID_LENGTH:
            raise serializers.ValidationError(
                (
                    f"User ID cannot exceed "
                    f"{MAX_USER_ID_LENGTH} characters."
                )
            )

        # Keep IDs predictable and safe for use in
        # authentication/rate-limit keys.
        if not re.fullmatch(
            r"[A-Za-z0-9._-]+",
            user_id,
        ):
            raise serializers.ValidationError(
                (
                    "User ID may contain only "
                    "letters, numbers, '.', '_' and '-'."
                )
            )

        if User.objects.filter(
            user_id=user_id
        ).exists():
            raise serializers.ValidationError(
                "This User ID is already registered."
            )

        return user_id

    # --------------------------------------------------
    # OBJECT VALIDATION
    # --------------------------------------------------

    def validate(
        self,
        attrs,
    ):
        password = attrs.get(
            "password"
        )

        password_confirm = attrs.pop(
            "password_confirm",
            None,
        )

        if not password:
            raise serializers.ValidationError(
                {
                    "password": (
                        "Password is required."
                    )
                }
            )

        if password_confirm is None:
            raise serializers.ValidationError(
                {
                    "password_confirm": (
                        "Password confirmation is required."
                    )
                }
            )

        if password != password_confirm:
            raise serializers.ValidationError(
                {
                    "password_confirm": (
                        "Passwords do not match."
                    )
                }
            )

        # Reject extremely weak patterns before Django's
        # configurable password validators run.
        if password.lower() in {
            "password",
            "password123",
            "password@123",
            "admin123",
            "qwerty123",
            "123456789012",
        }:
            raise serializers.ValidationError(
                {
                    "password": (
                        "This password is too common. "
                        "Choose a stronger password."
                    )
                }
            )

        user_like_data = {
            "user_id": attrs.get(
                "user_id",
                "",
            ),
            "email": attrs.get(
                "email",
                "",
            ),
            "first_name": attrs.get(
                "first_name",
                "",
            ),
            "last_name": attrs.get(
                "last_name",
                "",
            ),
        }

        temporary_user = User(
            **user_like_data
        )

        # Django's configured AUTH_PASSWORD_VALIDATORS
        # remain the source of truth for password quality.
        try:
            validate_password(
                password,
                user=temporary_user,
            )

        except DjangoValidationError as error:
            raise serializers.ValidationError(
                {
                    "password": list(
                        error.messages
                    )
                }
            )

        # Additional practical password checks.
        if len(
            set(password)
        ) < 5:
            raise serializers.ValidationError(
                {
                    "password": (
                        "Password must contain "
                        "more character variety."
                    )
                }
            )

        if (
            password.lower()
            == str(
                attrs.get(
                    "user_id",
                    "",
                )
            ).lower()
        ):
            raise serializers.ValidationError(
                {
                    "password": (
                        "Password cannot be the same "
                        "as the User ID."
                    )
                }
            )

        email_local_part = str(
            attrs.get(
                "email",
                "",
            )
        ).split(
            "@",
            1,
        )[0].lower()

        if (
            email_local_part
            and password.lower()
            == email_local_part
        ):
            raise serializers.ValidationError(
                {
                    "password": (
                        "Password cannot be the same "
                        "as the email username."
                    )
                }
            )

        return attrs

    # --------------------------------------------------
    # CREATE USER
    # --------------------------------------------------

    def create(
        self,
        validated_data,
    ):
        password = validated_data.pop(
            "password"
        )

        # password_confirm was already removed
        # inside validate().
        validated_data.pop(
            "password_confirm",
            None,
        )

        user = User(
            **validated_data,
            role=User.ROLE_USER,
            is_active=True,
        )

        user.set_password(
            password
        )

        user.save(
            using=self.Meta.model._default_manager.db
            if self.Meta.model._default_manager.db
            else None
        )

        return user


# --------------------------------------------------
# USER SERIALIZER
# --------------------------------------------------

class UserSerializer(
    serializers.ModelSerializer
):

    class Meta:

        model = User

        fields = [
            "id",
            "user_id",
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "role",
            "is_active",
            "created_at",
        ]

        read_only_fields = [
            "id",
            "user_id",
            "role",
            "is_active",
            "created_at",
        ]

    def validate_email(
        self,
        value,
    ):
        email = _normalize_email(
            value
        )

        user = self.instance

        queryset = User.objects.filter(
            email__iexact=email
        )

        if user is not None:
            queryset = queryset.exclude(
                pk=user.pk
            )

        if queryset.exists():
            raise serializers.ValidationError(
                "An account with this email already exists."
            )

        return email

    def validate_phone_number(
        self,
        value,
    ):
        phone = _normalize_phone(
            value
        )

        if not PHONE_PATTERN.fullmatch(
            phone
        ):
            raise serializers.ValidationError(
                (
                    "Enter a valid phone number "
                    "containing 10 to 15 digits, "
                    "optionally prefixed with '+'."
                )
            )

        user = self.instance

        queryset = User.objects.filter(
            phone_number=phone
        )

        if user is not None:
            queryset = queryset.exclude(
                pk=user.pk
            )

        if queryset.exists():
            raise serializers.ValidationError(
                "An account with this phone number already exists."
            )

        return phone
