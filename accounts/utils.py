from __future__ import annotations

import hashlib
import hmac
from typing import Any

import requests

from django.conf import settings


# ==================================================
# CLOUDFLARE TURNSTILE
# ==================================================

TURNSTILE_URL = (
    "https://challenges.cloudflare.com/"
    "turnstile/v0/siteverify"
)

TURNSTILE_TIMEOUT_SECONDS = 8


# ==================================================
# HASHING
# ==================================================

def sha256_hash(
    value: str,
) -> str:
    """
    Return a SHA-256 hexadecimal digest.

    Intended for non-password data such as fingerprints,
    identifiers, or integrity values.

    Never use this function for storing user passwords.
    Django's password hashing framework must be used.
    """

    if value is None:
        value = ""

    if not isinstance(
        value,
        str,
    ):
        value = str(value)

    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


# ==================================================
# CONSTANT-TIME SECRET COMPARISON
# ==================================================

def secure_compare(
    value_a: Any,
    value_b: Any,
) -> bool:
    """
    Compare two security-sensitive values using
    constant-time comparison.
    """

    if value_a is None or value_b is None:
        return False

    try:
        return hmac.compare_digest(
            str(value_a),
            str(value_b),
        )
    except TypeError:
        return False


# ==================================================
# CLIENT IP
# ==================================================

def get_client_ip(
    request,
) -> str:
    """
    Return the client IP address.

    X-Forwarded-For is trusted only when
    TRUST_PROXY_HEADERS is explicitly enabled.

    By default, REMOTE_ADDR is used because blindly
    trusting X-Forwarded-For allows clients to spoof
    their IP address and bypass IP-based security controls.
    """

    remote_addr = (
        request.META.get(
            "REMOTE_ADDR",
            "",
        )
        or ""
    ).strip()

    trust_proxy_headers = bool(
        getattr(
            settings,
            "TRUST_PROXY_HEADERS",
            False,
        )
    )

    if not trust_proxy_headers:
        return remote_addr or "unknown"

    forwarded = (
        request.META.get(
            "HTTP_X_FORWARDED_FOR",
            "",
        )
        or ""
    ).strip()

    if not forwarded:
        return remote_addr or "unknown"

    # X-Forwarded-For normally looks like:
    #
    # client, proxy1, proxy2
    #
    # The first value represents the original client
    # only when the complete proxy chain is trusted.

    first_ip = forwarded.split(
        ",",
        1,
    )[0].strip()

    return first_ip or remote_addr or "unknown"


# ==================================================
# TURNSTILE CONFIGURATION
# ==================================================

def _get_turnstile_secret() -> str:
    """
    Return the configured Cloudflare Turnstile secret.
    """

    secret = getattr(
        settings,
        "TURNSTILE_SECRET_KEY",
        "",
    )

    return str(
        secret or ""
    ).strip()


def is_turnstile_configured() -> bool:
    """
    Return whether Turnstile has been configured.

    This function does not perform network access.
    """

    return bool(
        _get_turnstile_secret()
    )


# ==================================================
# TURNSTILE VERIFICATION
# ==================================================

def verify_turnstile(
    token: str,
    remote_ip: str | None = None,
) -> bool:
    """
    Verify a Cloudflare Turnstile token.

    Security behaviour:

    - Empty tokens fail.
    - Missing server secret fails.
    - Network errors fail closed.
    - Invalid JSON fails closed.
    - Only explicit boolean True passes.

    The caller decides whether CAPTCHA should be
    mandatory based on configuration.
    """

    token = str(
        token or ""
    ).strip()

    if not token:
        return False

    secret = _get_turnstile_secret()

    if not secret:
        return False

    payload = {
        "secret": secret,
        "response": token,
    }

    remote_ip = str(
        remote_ip or ""
    ).strip()

    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        response = requests.post(
            TURNSTILE_URL,
            data=payload,
            timeout=TURNSTILE_TIMEOUT_SECONDS,
        )

        response.raise_for_status()

    except (
        requests.Timeout,
        requests.ConnectionError,
        requests.RequestException,
    ):
        return False

    try:
        result = response.json()
    except ValueError:
        return False

    if not isinstance(
        result,
        dict,
    ):
        return False

    return (
        result.get("success")
        is True
    )


# ==================================================
# TURNSTILE DETAILED RESULT
# ==================================================

def verify_turnstile_detailed(
    token: str,
    remote_ip: str | None = None,
) -> dict[str, Any]:
    """
    Return a structured Turnstile verification result.

    Useful for security logging and diagnostics without
    exposing the Turnstile secret key.

    Example:

    {
        "success": True,
        "error_codes": [],
        "hostname": "...",
        "action": "login",
    }
    """

    token = str(
        token or ""
    ).strip()

    if not token:
        return {
            "success": False,
            "error_codes": [
                "missing-input-response",
            ],
            "hostname": "",
            "action": "",
        }

    secret = _get_turnstile_secret()

    if not secret:
        return {
            "success": False,
            "error_codes": [
                "server-misconfiguration",
            ],
            "hostname": "",
            "action": "",
        }

    payload = {
        "secret": secret,
        "response": token,
    }

    remote_ip = str(
        remote_ip or ""
    ).strip()

    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        response = requests.post(
            TURNSTILE_URL,
            data=payload,
            timeout=TURNSTILE_TIMEOUT_SECONDS,
        )

        response.raise_for_status()

    except requests.Timeout:
        return {
            "success": False,
            "error_codes": [
                "verification-timeout",
            ],
            "hostname": "",
            "action": "",
        }

    except requests.ConnectionError:
        return {
            "success": False,
            "error_codes": [
                "verification-connection-error",
            ],
            "hostname": "",
            "action": "",
        }

    except requests.RequestException:
        return {
            "success": False,
            "error_codes": [
                "verification-request-error",
            ],
            "hostname": "",
            "action": "",
        }

    try:
        result = response.json()

    except ValueError:
        return {
            "success": False,
            "error_codes": [
                "invalid-verification-response",
            ],
            "hostname": "",
            "action": "",
        }

    if not isinstance(
        result,
        dict,
    ):
        return {
            "success": False,
            "error_codes": [
                "invalid-verification-response",
            ],
            "hostname": "",
            "action": "",
        }

    error_codes = result.get(
        "error-codes",
        [],
    )

    if not isinstance(
        error_codes,
        list,
    ):
        error_codes = []

    return {
        "success": (
            result.get("success")
            is True
        ),
        "error_codes": [
            str(code)
            for code in error_codes
            if code
        ],
        "hostname": str(
            result.get(
                "hostname",
                "",
            )
            or ""
        ),
        "action": str(
            result.get(
                "action",
                "",
            )
            or ""
        ),
    }


# ==================================================
# PUBLIC API
# ==================================================

__all__ = [
    "TURNSTILE_URL",
    "TURNSTILE_TIMEOUT_SECONDS",
    "sha256_hash",
    "secure_compare",
    "get_client_ip",
    "is_turnstile_configured",
    "verify_turnstile",
    "verify_turnstile_detailed",
]
