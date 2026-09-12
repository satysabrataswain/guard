import hashlib
import requests

from django.conf import settings


TURNSTILE_URL = (
    "https://challenges.cloudflare.com/turnstile/v0/siteverify"
)


def sha256_hash(value):
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def get_client_ip(request):

    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.META.get("REMOTE_ADDR")


def verify_turnstile(token, remote_ip=None):

    if not token:
        return False

    secret = settings.TURNSTILE_SECRET_KEY

    if not secret:
        return False

    data = {
        "secret": secret,
        "response": token,
    }

    if remote_ip:
        data["remoteip"] = remote_ip

    try:
        response = requests.post(
            TURNSTILE_URL,
            data=data,
            timeout=10,
        )

        response.raise_for_status()

        result = response.json()

        return result.get("success", False)

    except requests.RequestException:
        return False