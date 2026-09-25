from django.urls import path

from .views import (
    RegisterView,
    LoginView,
    MeView,
    LogoutView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    SecureTokenRefreshView,
)


urlpatterns = [

    path(
        "register/",
        RegisterView.as_view(),
        name="register",
    ),

    path(
        "login/",
        LoginView.as_view(),
        name="login",
    ),

    path(
        "token/refresh/",
        SecureTokenRefreshView.as_view(),
        name="token_refresh",
    ),

    path(
        "me/",
        MeView.as_view(),
        name="me",
    ),

    path(
        "password-reset/",
        PasswordResetRequestView.as_view(),
        name="password_reset_request",
    ),

    path(
        "password-reset/confirm/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),

    path(
        "logout/",
        LogoutView.as_view(),
        name="logout",
    ),
]