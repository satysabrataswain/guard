"""Public-web image presence tracking.

Uses Google Cloud Vision WEB_DETECTION as a web index provider.
Cyber Guard owns the orchestration, normalization and presentation of the
returned evidence; FaceSeek is not used.

The service can return:
- full image matches
- partial image matches
- pages containing matching images
- visually similar images
- web entities / best-guess labels

No public-web result is invented when the provider is unavailable.
"""

from __future__ import annotations

import base64
import os
from typing import Any

import requests


ENDPOINT = "https://vision.googleapis.com/v1/images:annotate"
TIMEOUT_SECONDS = 15
MAX_RESULTS = 20


def _empty(status: str, error: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "enabled": False,
        "status": status,
        "provider": "Google Cloud Vision Web Detection",
        "matches_found": 0,
        "full_matches": [],
        "partial_matches": [],
        "matching_pages": [],
        "visually_similar_images": [],
        "web_entities": [],
        "best_guess_labels": [],
    }
    if error:
        result["error"] = error
    return result


def _dedupe(items: list[dict[str, Any]], key: str = "url") -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for item in items:
        value = str(item.get(key, "")).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(item)
    return output


def track_image_on_public_web(file_path: str) -> dict[str, Any]:
    """Find public-web references to an uploaded local image.

    This is web-index discovery, not a guarantee that every occurrence on the
    internet has been found. Search engines can only return pages/images in
    their indexed corpus.
    """
    api_key = os.getenv("GOOGLE_CLOUD_VISION_API_KEY", "").strip()
    if not api_key:
        return _empty("NOT_CONFIGURED")

    try:
        with open(file_path, "rb") as image_file:
            content = base64.b64encode(image_file.read()).decode("ascii")
    except OSError as error:
        return _empty("READ_ERROR", str(error))

    payload = {
        "requests": [
            {
                "image": {"content": content},
                "features": [
                    {"type": "WEB_DETECTION", "maxResults": MAX_RESULTS},
                ],
            }
        ]
    }

    try:
        response = requests.post(
            ENDPOINT,
            params={"key": api_key},
            json=payload,
            timeout=TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as error:
        return _empty("ERROR", f"Web detection request failed: {error}")

    api_response = (data.get("responses") or [{}])[0]
    if api_response.get("error"):
        return _empty(
            "ERROR",
            str(api_response["error"].get("message", "Vision API error.")),
        )

    web = api_response.get("webDetection") or {}

    full_matches = [
        {"url": item.get("url", ""), "score": item.get("score")}
        for item in web.get("fullMatchingImages", [])
        if item.get("url")
    ]
    partial_matches = [
        {"url": item.get("url", ""), "score": item.get("score")}
        for item in web.get("partialMatchingImages", [])
        if item.get("url")
    ]
    similar = [
        {"url": item.get("url", ""), "score": item.get("score")}
        for item in web.get("visuallySimilarImages", [])
        if item.get("url")
    ]
    pages = [
        {
            "url": item.get("url", ""),
            "page_title": item.get("pageTitle"),
            "matching_image_url": item.get("fullMatchingImages", [{}])[0].get("url")
            if item.get("fullMatchingImages")
            else None,
        }
        for item in web.get("pagesWithMatchingImages", [])
        if item.get("url")
    ]
    entities = [
        {
            "entity_id": item.get("entityId"),
            "description": item.get("description"),
            "score": item.get("score"),
        }
        for item in web.get("webEntities", [])
        if item.get("description")
    ]
    labels = [
        {"label": item.get("label"), "language_code": item.get("languageCode")}
        for item in web.get("bestGuessLabels", [])
        if item.get("label")
    ]

    full_matches = _dedupe(full_matches)
    partial_matches = _dedupe(partial_matches)
    pages = _dedupe(pages)
    similar = _dedupe(similar)

    return {
        "enabled": True,
        "status": "MATCHES_FOUND" if (full_matches or partial_matches or pages) else "NO_MATCHES",
        "provider": "Google Cloud Vision Web Detection",
        "search_scope": "Public web pages and images indexed by the provider",
        "matches_found": len(full_matches) + len(partial_matches) + len(pages),
        "full_match_count": len(full_matches),
        "partial_match_count": len(partial_matches),
        "matching_page_count": len(pages),
        "similar_image_count": len(similar),
        "full_matches": full_matches,
        "partial_matches": partial_matches,
        "matching_pages": pages,
        "visually_similar_images": similar,
        "web_entities": entities,
        "best_guess_labels": labels,
        "note": (
            "Results are limited to public web content indexed by the provider; "
            "they are not a complete record of every occurrence on the internet."
        ),
    }
