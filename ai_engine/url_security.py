"""Combined URL security evidence layer."""

from __future__ import annotations

from typing import Any
from datetime import datetime, timezone
import socket
import ssl
from urllib.parse import urlparse

import requests

from ai_engine.google_safe_browsing import check_url_with_google
from ai_engine.trained_classifiers import analyze_phishing_url_ml
from ai_engine.url_redirect import resolve_redirect_chain


def _severity(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "SAFE"


def _clamp(score: float) -> float:
    return round(max(0.0, min(100.0, float(score))), 2)



def _get_url_intelligence(final_url: str) -> dict[str, Any]:
    parsed = urlparse(final_url)
    host = (parsed.hostname or "").lower()
    result: dict[str, Any] = {
        "source_url": final_url,
        "brand": None,
        "tld": host.rsplit(".", 1)[-1] if "." in host else None,
        "ip_address": None,
        "location": None,
        "hosting_provider": None,
        "asn": None,
        "certificate": None,
        "page_title": None,
        "status_code": None,
        "content_type": None,
        "detection_date": datetime.now(timezone.utc).isoformat(),
    }
    if not host:
        return result

    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        result["ip_address"] = next((item[4][0] for item in infos if item[4]), None)
    except (OSError, socket.gaierror):
        pass

    ip = result["ip_address"]
    if ip:
        try:
            geo = requests.get(f"https://ipwho.is/{ip}", timeout=3).json()
            if geo.get("success"):
                result["location"] = ", ".join(
                    part for part in [geo.get("city"), geo.get("region"), geo.get("country")] if part
                ) or None
                connection = geo.get("connection") or {}
                result["hosting_provider"] = connection.get("org") or connection.get("isp")
                result["asn"] = connection.get("asn")
        except (requests.RequestException, ValueError, TypeError):
            pass

    if parsed.scheme == "https":
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, parsed.port or 443), timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname=host) as sock:
                    cert = sock.getpeercert()
            subject = dict(item[0] for item in cert.get("subject", ()))
            issuer = dict(item[0] for item in cert.get("issuer", ()))
            result["certificate"] = {
                "subject": subject.get("commonName"),
                "issuer": issuer.get("commonName") or issuer.get("organizationName"),
                "valid_from": cert.get("notBefore"),
                "valid_until": cert.get("notAfter"),
            }
        except (OSError, ssl.SSLError, ValueError):
            result["certificate"] = {"status": "UNAVAILABLE"}

    try:
        response = requests.get(
            final_url,
            headers={"User-Agent": "GUARD-Security-Scanner/1.0"},
            timeout=4,
            stream=True,
        )
        result["status_code"] = response.status_code
        result["content_type"] = response.headers.get("Content-Type")
        content = response.text[:200_000]
        response.close()
        import re
        title_match = re.search(r"<title[^>]*>(.*?)</title>", content, re.I | re.S)
        if title_match:
            result["page_title"] = re.sub(r"\\s+", " ", title_match.group(1)).strip()[:300]
    except requests.RequestException:
        pass

    return result

def analyze_url_security(url: str) -> dict[str, Any]:
    original = str(url or "").strip()
    candidate = original if "://" in original else f"https://{original}"

    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return {
            "is_valid": False,
            "risk_score": 0.0,
            "severity": "SAFE",
            "error": "Invalid HTTP/HTTPS URL.",
        }

    ml = analyze_phishing_url_ml(candidate)
    redirect = resolve_redirect_chain(candidate)

    final_url = str(redirect.get("final_url") or candidate)
    google_original = check_url_with_google(candidate)
    url_intelligence = _get_url_intelligence(final_url)

    google_final = (
        check_url_with_google(final_url)
        if final_url != candidate
        else google_original
    )

    ml_score = float((ml or {}).get("risk_score", 0.0))

    redirect_score = 0.0
    redirect_indicators: list[str] = []

    redirect_count = int(redirect.get("redirect_count", 0) or 0)
    if redirect_count:
        redirect_score += min(25.0, redirect_count * 8.0)
        redirect_indicators.append(
            f"URL redirect chain contains {redirect_count} redirect(s)."
        )

    original_host = (urlparse(candidate).hostname or "").lower()
    final_host = (urlparse(final_url).hostname or "").lower()

    if original_host and final_host and original_host != final_host:
        redirect_score += 20.0
        redirect_indicators.append(
            f"Final destination URL: {final_url}"
        )

    matches = []
    for source, result in (
        ("original_url", google_original),
        ("final_url", google_final),
    ):
        for match in result.get("matches", []):
            if isinstance(match, dict):
                matches.append({"source": source, **match})

    google_score = 90.0 if matches else 0.0
    final_score = _clamp(max(ml_score, redirect_score, google_score))

    indicators = list((ml or {}).get("indicators", []))
    indicators.extend(redirect_indicators)

    if matches:
        indicators.append(
            "Google Safe Browsing matched a listed threat for the original or final URL."
        )
    elif google_original.get("checked"):
        indicators.append(
            "Google Safe Browsing found no listed threat for the original URL."
        )
        if final_url != candidate and google_final.get("checked"):
            indicators.append(
                "Google Safe Browsing found no listed threat for the final destination URL."
            )
    elif google_original.get("error"):
        indicators.append(
            f"Google Safe Browsing unavailable: {google_original['error']}"
        )

    return {
        "is_valid": True,
        "analysis_type": "url_security_combined",
        "risk_score": final_score,
        "severity": _severity(final_score),
        "prediction": (ml or {}).get("prediction", "GOOGLE_SAFE_BROWSING_ONLY"),
        "confidence": (ml or {}).get("confidence", 0.0),
        "indicators": list(dict.fromkeys(indicators)),
        "features": {
            "trained_model": ml or {
                "available": False,
                "reason": "Trained phishing URL model is unavailable.",
            },
            "redirect_analysis": redirect,
            "google_safe_browsing": {
                "original_url": google_original,
                "final_url": google_final,
                "matched_threats": matches,
            },
            "risk_components": {
                "trained_phishing_url_model": _clamp(ml_score),
                "redirect_security": _clamp(redirect_score),
                "google_safe_browsing": google_score,
            },
            "original_url": candidate,
            "final_url": final_url,
            "original_domain": original_host,
            "final_domain": final_host,
            "url_intelligence": url_intelligence,
        },
        "recommendation": (
            "Do not open the URL until it is verified."
            if final_score >= 60
            else "Review the trained model, redirect analysis and Google Safe Browsing evidence before trusting the URL."
        ),
    }
