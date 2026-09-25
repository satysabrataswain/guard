"""
Public-web image provenance and reverse-image evidence.

This module does not use FaceSeek. It keeps Cyber Guard's own local
fingerprint and sends a resized copy to an optional public visual-search
provider only to discover indexed public webpages/images.

The returned matches are evidence, not proof that an image is identical
unless the provider explicitly reports an image/page match.
"""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
from typing import Any

import requests
from PIL import Image


BING_ENDPOINT = "https://api.bing.microsoft.com/v7.0/images/visualsearch"
MAX_PROVIDER_BYTES = 950 * 1024
TIMEOUT_SECONDS = 20


def _sha256(file_path: str) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _average_hash(image: Image.Image) -> str:
    gray = image.convert("L").resize((8, 8))
    pixels = list(gray.getdata())
    average = sum(pixels) / len(pixels)
    return "".join("1" if pixel >= average else "0" for pixel in pixels)


def _fingerprint(file_path: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "sha256": _sha256(file_path),
        "average_hash": None,
        "width": None,
        "height": None,
        "format": None,
    }
    with Image.open(file_path) as image:
        result["width"], result["height"] = image.size
        result["format"] = image.format
        result["average_hash"] = _average_hash(image)
    return result


def _prepare_provider_image(file_path: str) -> bytes:
    with Image.open(file_path) as image:
        image = image.convert("RGB")
        image.thumbnail((1500, 1500))

        quality = 90
        while quality >= 45:
            buffer = io.BytesIO()
            image.save(buffer, format="JPEG", quality=quality, optimize=True)
            payload = buffer.getvalue()
            if len(payload) <= MAX_PROVIDER_BYTES:
                return payload
            quality -= 5

        buffer = io.BytesIO()
        image.save(buffer, format="JPEG", quality=40, optimize=True)
        return buffer.getvalue()


def _walk_provider_results(value: Any, output: list[dict[str, Any]]) -> None:
    if isinstance(value, dict):
        host_page = value.get("hostPageUrl")
        content_url = value.get("contentUrl")
        name = value.get("name") or value.get("displayName")
        thumbnail = value.get("thumbnailUrl")

        if host_page or content_url:
            output.append(
                {
                    "title": str(name or "Web image result"),
                    "page_url": host_page,
                    "image_url": content_url,
                    "thumbnail_url": thumbnail,
                    "source": "Bing Visual Search",
                }
            )

        for child in value.values():
            _walk_provider_results(child, output)

    elif isinstance(value, list):
        for child in value:
            _walk_provider_results(child, output)


def _deduplicate(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []

    for item in matches:
        key = (
            item.get("page_url")
            or item.get("image_url")
            or item.get("thumbnail_url")
        )
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(item)

    return result


def _provider_search(image_bytes: bytes) -> dict[str, Any]:
    api_key = os.getenv("BING_VISUAL_SEARCH_API_KEY", "").strip()

    if not api_key:
        return {
            "status": "NOT_CONFIGURED",
            "provider": "Bing Visual Search",
            "message": (
                "Public-web image tracking is ready, but "
                "BING_VISUAL_SEARCH_API_KEY is not configured."
            ),
            "matches": [],
        }

    response = requests.post(
        BING_ENDPOINT,
        headers={
            "Ocp-Apim-Subscription-Key": api_key,
        },
        files={
            "image": (
                "cyber_guard_image.jpg",
                image_bytes,
                "image/jpeg",
            )
        },
        timeout=TIMEOUT_SECONDS,
    )

    response.raise_for_status()
    payload = response.json()

    matches: list[dict[str, Any]] = []
    _walk_provider_results(payload, matches)
    matches = _deduplicate(matches)

    return {
        "status": "MATCHES_FOUND" if matches else "NO_MATCHES_RETURNED",
        "provider": "Bing Visual Search",
        "matches": matches[:50],
        "match_count": len(matches),
        "provider_pages_including_count": (
            payload.get("image", {})
            .get("insightsMetadata", {})
            .get("pagesIncludingCount")
        ),
        "web_search_url": (
            payload.get("image", {})
            .get("imageInsightsToken")
        ),
    }


def analyze_public_web_presence(
    file_path: str,
    file_name: str = "",
) -> dict[str, Any]:
    """
    Build Cyber Guard's own fingerprint and discover public-web evidence.

    Important:
    - SHA-256 is an exact-byte fingerprint.
    - Average hash is a local perceptual fingerprint.
    - Public-web matches depend on the provider's indexed web coverage.
    - No provider result is converted into a deepfake verdict.
    """

    extension = Path(file_name or file_path).suffix.lower()

    try:
        fingerprint = _fingerprint(file_path)
        image_bytes = _prepare_provider_image(file_path)
    except Exception as error:
        return {
            "status": "IMAGE_READ_ERROR",
            "provider": None,
            "fingerprint": {},
            "matches": [],
            "error": str(error),
        }

    result = _provider_search(image_bytes)
    result["fingerprint"] = fingerprint
    result["file_name"] = file_name
    result["extension"] = extension
    result["provider_input"] = {
        "resized_for_search": True,
        "max_upload_bytes": MAX_PROVIDER_BYTES,
        "max_dimension": 1500,
    }
    result["coverage_note"] = (
        "Results represent public pages/images returned by the configured "
        "visual-search index. No reverse-image service can guarantee every "
        "page on the public internet."
    )
    return result
