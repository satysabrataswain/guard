from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):

    password = serializers.CharField(
        write_only=True,
        min_length=8
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
        ]

    def create(self, validated_data):

        password = validated_data.pop("password")

        user = User(
            **validated_data,
            role=User.ROLE_USER,
            is_active=True
        )

        user.set_password(password)
        user.save()

        return user


class UserSerializer(serializers.ModelSerializer):

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