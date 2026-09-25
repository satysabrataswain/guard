from __future__ import annotations

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed


class BrowserPrivacyTokenAuthentication(BaseAuthentication):
    """
    Authenticate only short-lived Cyber Guard browser scanner tokens.

    These tokens are deliberately separate from the normal user JWTs so the
    browser extension never needs the user's main access/refresh token.
    """

    keyword = b"Bearer"

    def authenticate(self, request):
        header = get_authorization_header(request).split()

        if not header:
            return None

        if header[0].lower() != self.keyword.lower():
            return None

        if len(header) != 2:
            raise AuthenticationFailed("Invalid browser scanner authorization header.")

        token = header[1].decode("utf-8", errors="ignore")

        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=["HS256"],
                options={"require": ["exp", "iat", "sub", "purpose", "jti"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationFailed("Browser scanner token is invalid or expired.") from exc

        if payload.get("purpose") != "browser_privacy_scan":
            raise AuthenticationFailed("Invalid browser scanner token purpose.")

        try:
            user_id = int(payload["sub"])
        except (TypeError, ValueError, KeyError) as exc:
            raise AuthenticationFailed("Invalid browser scanner identity.") from exc

        user = get_user_model().objects.filter(
            pk=user_id,
            is_active=True,
        ).first()

        if user is None:
            raise AuthenticationFailed("Browser scanner user is no longer active.")

        return (user, token)

    def authenticate_header(self, request):
        return "Bearer"
