from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model

from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    RegisterSerializer,
    UserSerializer,
)

from .utils import (
    verify_turnstile,
    get_client_ip,
)

from audit_logs.models import AuditLog


User = get_user_model()


class RegisterView(generics.CreateAPIView):

    queryset = User.objects.all()

    serializer_class = RegisterSerializer

    permission_classes = [AllowAny]

    def perform_create(self, serializer):

        user = serializer.save()

        AuditLog.objects.create(
            user=user,
            action="REGISTER",
            ip_address=get_client_ip(self.request),
            user_agent=self.request.META.get(
                "HTTP_USER_AGENT",
                ""
            ),
            description="New user registered.",
            status="SUCCESS",
        )


class LoginView(APIView):

    permission_classes = [AllowAny]

    def post(self, request):

        user_id = request.data.get("user_id")
        password = request.data.get("password")

        # --------------------------------
        # CAPTCHA
        # --------------------------------

        # captcha_token = request.data.get(
        #     "cf-turnstile-response"
        # )

        ip_address = get_client_ip(request)

        # if not verify_turnstile(
        #     captcha_token,
        #     ip_address
        # ):

        #     AuditLog.objects.create(
        #         action="CAPTCHA_FAILED",
        #         ip_address=ip_address,
        #         user_agent=request.META.get(
        #             "HTTP_USER_AGENT",
        #             ""
            #     ),
            #     description="Turnstile verification failed.",
            #     status="FAILED",
            # )

            # return Response(
            #     {
            #         "detail": "CAPTCHA verification failed."
            #     },
            #     status=status.HTTP_400_BAD_REQUEST,
            # )

        # --------------------------------
        # Required fields
        # --------------------------------

        if not user_id or not password:

            return Response(
                {
                    "detail":
                    "User ID and password are required."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # --------------------------------
        # Find user
        # --------------------------------

        try:

            user = User.objects.get(
                user_id=user_id
            )

        except User.DoesNotExist:

            AuditLog.objects.create(
                action="FAILED_LOGIN",
                ip_address=ip_address,
                user_agent=request.META.get(
                    "HTTP_USER_AGENT",
                    ""
                ),
                description="Login attempted with unknown User ID.",
                status="FAILED",
            )

            return Response(
                {
                    "detail":
                    "Invalid User ID or password."
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # --------------------------------
        # Account status
        # --------------------------------

        if not user.is_active:

            AuditLog.objects.create(
                user=user,
                action="FAILED_LOGIN",
                ip_address=ip_address,
                user_agent=request.META.get(
                    "HTTP_USER_AGENT",
                    ""
                ),
                description="Inactive account attempted login.",
                status="FAILED",
            )

            return Response(
                {
                    "detail":
                    "Your account is inactive. Contact admin."
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        # --------------------------------
        # Password authentication
        # --------------------------------

        authenticated_user = authenticate(
            request=request,
            username=user.username,
            password=password,
        )

        if authenticated_user is None:

            AuditLog.objects.create(
                user=user,
                action="FAILED_LOGIN",
                ip_address=ip_address,
                user_agent=request.META.get(
                    "HTTP_USER_AGENT",
                    ""
                ),
                description="Incorrect password.",
                status="FAILED",
            )

            return Response(
                {
                    "detail":
                    "Invalid User ID or password."
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # --------------------------------
        # JWT
        # --------------------------------

        refresh = RefreshToken.for_user(user)

        # --------------------------------
        # Successful audit
        # --------------------------------

        AuditLog.objects.create(
            user=user,
            action="LOGIN",
            ip_address=ip_address,
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                ""
            ),
            description="Successful login.",
            status="SUCCESS",
        )

        return Response(
            {
                "message": "Login successful.",

                "access": str(
                    refresh.access_token
                ),

                "refresh": str(refresh),

                "user": UserSerializer(
                    user
                ).data,
            },
            status=status.HTTP_200_OK,
        )


class MeView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        return Response(
            UserSerializer(
                request.user
            ).data
        )


class LogoutView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        refresh_token = request.data.get(
            "refresh"
        )

        if not refresh_token:

            return Response(
                {
                    "detail":
                    "Refresh token is required."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:

            token = RefreshToken(
                refresh_token
            )

            token.blacklist()

            AuditLog.objects.create(
                user=request.user,
                action="LOGOUT",
                ip_address=get_client_ip(request),
                user_agent=request.META.get(
                    "HTTP_USER_AGENT",
                    ""
                ),
                description="User logged out.",
                status="SUCCESS",
            )

            return Response(
                {
                    "message":
                    "Logout successful."
                }
            )

        except Exception:

            return Response(
                {
                    "detail":
                    "Invalid refresh token."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )