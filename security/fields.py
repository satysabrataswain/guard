from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.core.exceptions import ImproperlyConfigured
from django.db import models


_PREFIX = "v1."
_NONCE_SIZE = 12
_KEY_SIZE = 32
_AAD = b"cyber-guard-db-v1"


def _get_key() -> bytes:
    value = os.getenv("DATA_ENCRYPTION_KEY", "").strip()
    if not value:
        raise ImproperlyConfigured(
            "DATA_ENCRYPTION_KEY is not configured. "
            "Generate a 256-bit key and keep it only in the environment."
        )
    try:
        key = base64.urlsafe_b64decode(value.encode("ascii"))
    except Exception as exc:
        raise ImproperlyConfigured(
            "DATA_ENCRYPTION_KEY must be URL-safe base64."
        ) from exc
    if len(key) != _KEY_SIZE:
        raise ImproperlyConfigured(
            "DATA_ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256)."
        )
    return key


def encrypt_value(value: str) -> str:
    if value == "":
        return ""
    key = _get_key()
    nonce = os.urandom(_NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, value.encode("utf-8"), _AAD)
    return _PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_value(value: str) -> str:
    if value in (None, ""):
        return value or ""
    if not isinstance(value, str) or not value.startswith(_PREFIX):
        # Backward compatibility for records created before encryption.
        return value
    try:
        raw = base64.urlsafe_b64decode(value[len(_PREFIX):].encode("ascii"))
        nonce, ciphertext = raw[:_NONCE_SIZE], raw[_NONCE_SIZE:]
        return AESGCM(_get_key()).decrypt(nonce, ciphertext, _AAD).decode("utf-8")
    except Exception as exc:
        raise ImproperlyConfigured(
            "Encrypted database value could not be decrypted. "
            "Check DATA_ENCRYPTION_KEY."
        ) from exc


class EncryptedTextField(models.TextField):
    """AES-256-GCM encrypted TextField with transparent application-level decryption."""

    description = "AES-256-GCM encrypted text"

    def get_prep_value(self, value: Any) -> str:
        value = super().get_prep_value(value)
        if value is None:
            return None
        return encrypt_value(str(value))

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return decrypt_value(value)

    def to_python(self, value):
        if value is None:
            return value
        if isinstance(value, str):
            return decrypt_value(value)
        return value


class EncryptedJSONField(models.TextField):
    """JSON-compatible field stored as AES-256-GCM encrypted text."""

    description = "AES-256-GCM encrypted JSON"

    def get_prep_value(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            payload = value
        else:
            payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        return encrypt_value(payload)

    def from_db_value(self, value, expression, connection):
        if value in (None, ""):
            return {}
        raw = decrypt_value(value)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    def to_python(self, value):
        if value in (None, ""):
            return {}
        if isinstance(value, (dict, list, int, float, bool)):
            return value
        raw = decrypt_value(value)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
