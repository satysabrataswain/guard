from __future__ import annotations

import os
import re
from typing import Any

import requests


SAFE_BROWSING_ENDPOINT = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def check_url_with_google(url: str, timeout: int = 8) -> dict[str, Any]:
    """
    Check a URL against Google Safe Browsing threat lists.

    The API key is read from GOOGLE_SAFE_BROWSING_API_KEY.
    If the key is missing or the service cannot be reached, the result is
    reported as unavailable rather than treating the URL as malicious.
    """

    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

    result: dict[str, Any] = {
        "enabled": bool(api_key),
        "checked": False,
        "status": "NOT_CONFIGURED" if not api_key else "PENDING",
        "safe": None,
        "matched": False,
        "matches": [],
        "error": "",
        "provider": "Google Safe Browsing",
        "url": url,
    }

    if not api_key:
        result["error"] = "GOOGLE_SAFE_BROWSING_API_KEY is not configured."
        result["status"] = "NOT_CONFIGURED"
        return result

    payload = {
        "client": {
            "clientId": "cyber-guard",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(
            SAFE_BROWSING_ENDPOINT,
            params={"key": api_key},
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json() if response.content else {}

        matches = data.get("matches") or []
        normalized_matches = []

        for match in matches:
            if not isinstance(match, dict):
                continue

            normalized_matches.append(
                {
                    "threat_type": match.get("threatType", "UNKNOWN"),
                    "platform_type": match.get("platformType", "UNKNOWN"),
                    "threat_entry_type": match.get(
                        "threatEntryType", "UNKNOWN"
                    ),
                    "cache_duration": match.get("cacheDuration", ""),
                }
            )

        result.update(
            {
                "checked": True,
                "safe": len(normalized_matches) == 0,
                "matched": bool(normalized_matches),
                "matches": normalized_matches,
                "status": "THREAT_FOUND" if normalized_matches else "SAFE",
            }
        )
        return result

    except requests.RequestException as exc:
        safe_error = str(exc)
        safe_error = re.sub(r"([?&]key=)[^&\\s]+", r"\\1[REDACTED]", safe_error)
        result["error"] = f"Google Safe Browsing request failed: {safe_error}"
        result["status"] = "ERROR"
        return result
    except ValueError as exc:
        result["error"] = f"Google Safe Browsing returned invalid JSON: {exc}"
        result["status"] = "ERROR"
        return result
