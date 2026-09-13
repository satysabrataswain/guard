from __future__ import annotations

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.core.cache import cache

from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework_simplejwt.tokens import RefreshToken

from audit_logs.models import AuditLog

from .serializers import (
    RegisterSerializer,
    UserSerializer,
)

from .utils import (
    get_client_ip,
    verify_turnstile,
)


User = get_user_model()


# --------------------------------------------------
# LOGIN SECURITY CONFIGURATION
# --------------------------------------------------

LOGIN_MAX_ATTEMPTS = 5

LOGIN_WINDOW_SECONDS = 15 * 60

LOGIN_LOCKOUT_SECONDS = 15 * 60


def _login_cache_key(
    ip_address: str,
    user_id: str,
) -> str:
    safe_ip = str(
        ip_address or "unknown"
    ).strip()

    safe_user_id = str(
        user_id or "unknown"
    ).strip().lower()

    return (
        f"guard:login-attempts:"
        f"{safe_ip}:{safe_user_id}"
    )


def _login_lock_key(
    ip_address: str,
    user_id: str,
) -> str:
    safe_ip = str(
        ip_address or "unknown"
    ).strip()

    safe_user_id = str(
        user_id or "unknown"
    ).strip().lower()

    return (
        f"guard:login-lock:"
        f"{safe_ip}:{safe_user_id}"
    )


def _get_login_attempts(
    ip_address: str,
    user_id: str,
) -> int:
    value = cache.get(
        _login_cache_key(
            ip_address,
            user_id,
        ),
        0,
    )

    try:
        return int(value)
    except (
        TypeError,
        ValueError,
    ):
        return 0


def _record_failed_login(
    ip_address: str,
    user_id: str,
) -> int:
    attempts_key = _login_cache_key(
        ip_address,
        user_id,
    )

    attempts = _get_login_attempts(
        ip_address,
        user_id,
    )

    attempts += 1

    cache.set(
        attempts_key,
        attempts,
        timeout=LOGIN_WINDOW_SECONDS,
    )

    if attempts >= LOGIN_MAX_ATTEMPTS:
        cache.set(
            _login_lock_key(
                ip_address,
                user_id,
            ),
            True,
            timeout=LOGIN_LOCKOUT_SECONDS,
        )

    return attempts


def _clear_failed_logins(
    ip_address: str,
    user_id: str,
) -> None:
    cache.delete(
        _login_cache_key(
            ip_address,
            user_id,
        )
    )

    cache.delete(
        _login_lock_key(
            ip_address,
            user_id,
        )
    )


def _is_login_locked(
    ip_address: str,
    user_id: str,
) -> bool:
    return bool(
        cache.get(
            _login_lock_key(
                ip_address,
                user_id,
            ),
            False,
        )
    )


def _captcha_is_configured() -> bool:
    """
    CAPTCHA becomes mandatory only when a Turnstile
    secret key is configured.

    This keeps local development usable while ensuring
    production can enforce CAPTCHA by configuration.
    """

    secret = getattr(
        settings,
        "TURNSTILE_SECRET_KEY",
        "",
    )

    return bool(
        str(secret or "").strip()
    )


def _get_captcha_token(
    request,
) -> str:
    token = request.data.get(
        "cf-turnstile-response"
    )

    if not token:
        token = request.data.get(
            "captcha_token"
        )

    if not token:
        token = request.data.get(
            "turnstile_token"
        )

    return str(
        token or ""
    ).strip()


def _audit_login_failure(
    request,
    description: str,
    user=None,
):
    AuditLog.objects.create(
        user=user,
        action="FAILED_LOGIN",
        ip_address=get_client_ip(
            request
        ),
        user_agent=request.META.get(
            "HTTP_USER_AGENT",
            "",
        ),
        description=description,
        status="FAILED",
    )


class RegisterView(
    generics.CreateAPIView
):
    queryset = User.objects.all()

    serializer_class = RegisterSerializer

    permission_classes = [
        AllowAny
    ]

    def perform_create(
        self,
        serializer,
    ):
        user = serializer.save()

        AuditLog.objects.create(
            user=user,
            action="REGISTER",
            ip_address=get_client_ip(
                self.request
            ),
            user_agent=self.request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                "New user registered."
            ),
            status="SUCCESS",
        )


class LoginView(APIView):
    permission_classes = [
        AllowAny
    ]

    def post(
        self,
        request,
    ):
        user_id = str(
            request.data.get(
                "user_id",
                "",
            )
        ).strip()

        password = request.data.get(
            "password"
        )

        ip_address = get_client_ip(
            request
        )

        # --------------------------------------------------
        # REQUIRED FIELDS
        # --------------------------------------------------

        if not user_id or not password:
            return Response(
                {
                    "detail": (
                        "User ID and password "
                        "are required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # --------------------------------------------------
        # BRUTE-FORCE / LOGIN LOCKOUT
        # --------------------------------------------------

        if _is_login_locked(
            ip_address,
            user_id,
        ):
            _audit_login_failure(
                request,
                (
                    "Login blocked because the "
                    "account/IP combination is "
                    "temporarily locked after "
                    "repeated failed attempts."
                ),
            )

            return Response(
                {
                    "detail": (
                        "Too many failed login attempts. "
                        "Try again later."
                    )
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        # --------------------------------------------------
        # CAPTCHA
        # --------------------------------------------------

        if _captcha_is_configured():
            captcha_token = _get_captcha_token(
                request
            )

            if not captcha_token:
                _audit_login_failure(
                    request,
                    (
                        "Login rejected because "
                        "CAPTCHA verification was required "
                        "but no CAPTCHA token was supplied."
                    ),
                )

                return Response(
                    {
                        "detail": (
                            "CAPTCHA verification "
                            "is required."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            captcha_valid = verify_turnstile(
                captcha_token,
                ip_address,
            )

            if not captcha_valid:
                _audit_login_failure(
                    request,
                    (
                        "Turnstile CAPTCHA "
                        "verification failed."
                    ),
                )

                return Response(
                    {
                        "detail": (
                            "CAPTCHA verification "
                            "failed."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # --------------------------------------------------
        # FIND USER
        # --------------------------------------------------

        try:
            user = User.objects.get(
                user_id=user_id
            )

        except User.DoesNotExist:
            attempts = _record_failed_login(
                ip_address,
                user_id,
            )

            _audit_login_failure(
                request,
                (
                    "Login attempted with unknown "
                    f"User ID. Failed attempts: {attempts}."
                ),
            )

            return Response(
                {
                    "detail": (
                        "Invalid User ID "
                        "or password."
                    )
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # --------------------------------------------------
        # ACCOUNT STATUS
        # --------------------------------------------------

        if not user.is_active:
            _audit_login_failure(
                request,
                (
                    "Inactive account attempted login."
                ),
                user=user,
            )

            return Response(
                {
                    "detail": (
                        "Your account is inactive. "
                        "Contact admin."
                    )
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        # --------------------------------------------------
        # PASSWORD AUTHENTICATION
        # --------------------------------------------------

        authenticated_user = authenticate(
            request=request,
            username=user.username,
            password=password,
        )

        if authenticated_user is None:
            attempts = _record_failed_login(
                ip_address,
                user_id,
            )

            _audit_login_failure(
                request,
                (
                    "Incorrect password. "
                    f"Failed attempts: {attempts}."
                ),
                user=user,
            )

            if attempts >= LOGIN_MAX_ATTEMPTS:
                return Response(
                    {
                        "detail": (
                            "Too many failed login attempts. "
                            "Your login is temporarily locked."
                        )
                    },
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            return Response(
                {
                    "detail": (
                        "Invalid User ID "
                        "or password."
                    ),
                    "remaining_attempts": max(
                        0,
                        LOGIN_MAX_ATTEMPTS - attempts,
                    ),
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # --------------------------------------------------
        # SUCCESSFUL AUTHENTICATION
        # --------------------------------------------------

        _clear_failed_logins(
            ip_address,
            user_id,
        )

        # --------------------------------------------------
        # JWT TOKEN CREATION
        # --------------------------------------------------

        refresh = RefreshToken.for_user(
            authenticated_user
        )

        # --------------------------------------------------
        # SUCCESS AUDIT
        # --------------------------------------------------

        AuditLog.objects.create(
            user=authenticated_user,
            action="LOGIN",
            ip_address=ip_address,
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                "Successful login."
            ),
            status="SUCCESS",
        )

        # --------------------------------------------------
        # RESPONSE
        # --------------------------------------------------

        return Response(
            {
                "message": (
                    "Login successful."
                ),
                "access": str(
                    refresh.access_token
                ),
                "refresh": str(
                    refresh
                ),
                "user": UserSerializer(
                    authenticated_user
                ).data,
            },
            status=status.HTTP_200_OK,
        )


class MeView(APIView):
    permission_classes = [
        IsAuthenticated
    ]

    def get(
        self,
        request,
    ):
        return Response(
            UserSerializer(
                request.user
            ).data,
            status=status.HTTP_200_OK,
        )


class LogoutView(APIView):
    permission_classes = [
        IsAuthenticated
    ]

    def post(
        self,
        request,
    ):
        refresh_token = str(
            request.data.get(
                "refresh",
                ""
            )
        ).strip()

        if not refresh_token:
            return Response(
                {
                    "detail": (
                        "Refresh token "
                        "is required."
                    )
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
                ip_address=get_client_ip(
                    request
                ),
                user_agent=request.META.get(
                    "HTTP_USER_AGENT",
                    "",
                ),
                description=(
                    "User logged out and "
                    "refresh token was blacklisted."
                ),
                status="SUCCESS",
            )

            return Response(
                {
                    "message": (
                        "Logout successful."
                    )
                },
                status=status.HTTP_200_OK,
            )

        except Exception:
            AuditLog.objects.create(
                user=request.user,
                action="LOGOUT",
                ip_address=get_client_ip(
                    request
                ),
                user_agent=request.META.get(
                    "HTTP_USER_AGENT",
                    "",
                ),
                description=(
                    "Logout failed because "
                    "the supplied refresh token "
                    "was invalid."
                ),
                status="FAILED",
            )

            return Response(
                {
                    "detail": (
                        "Invalid refresh token."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
