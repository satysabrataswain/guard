"""
Phishing URL Detection Engine

This module performs explainable, rule-based phishing risk analysis.

Important:
- This is a detection layer, not a guarantee of maliciousness.
- HTTPS does NOT imply that a URL is safe.
- URL shorteners are treated as a risk signal, not automatic phishing.
- Reputation, DNS, redirect-chain and external threat-intelligence checks
  can be added later without changing the public interface.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_URL_LENGTH = 2048

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc",
    "lnkd.in",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "password",
    "credential",
    "wallet",
    "payment",
    "invoice",
    "refund",
    "bank",
    "banking",
    "confirm",
    "confirmation",
    "unlock",
    "suspend",
    "suspended",
    "urgent",
    "alert",
    "webscr",
    "recover",
    "authentication",
    "authorize",
    "authorization",
}

HIGH_RISK_TLDS = {
    "zip",
    "mov",
    "click",
    "top",
    "xyz",
    "work",
    "country",
    "gq",
    "tk",
    "ml",
    "cf",
}

BRAND_NAMES = {
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "whatsapp",
    "netflix",
    "linkedin",
    "github",
    "dropbox",
    "docusign",
    "adobe",
    "outlook",
}

DANGEROUS_FILE_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".msi",
    ".js",
    ".vbs",
    ".ps1",
    ".jar",
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _clamp_score(score: float) -> float:
    """Keep score inside 0-100."""
    return round(max(0.0, min(100.0, score)), 2)


def _get_severity(score: float) -> str:
    """Convert numerical score into platform severity."""

    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"

    return "SAFE"


def _normalize_url(url: str) -> str:
    """Normalize URL without performing any network request."""

    url = str(url).strip()

    if not url:
        return ""

    # Remove surrounding whitespace.
    url = url.strip()

    # Add scheme when user supplies example.com/path.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = f"http://{url}"

    return url


def _is_valid_http_url(parsed) -> bool:
    """Check whether URL uses HTTP or HTTPS and has a hostname."""

    return (
        parsed.scheme.lower() in {"http", "https"}
        and bool(parsed.hostname)
    )


def _is_ip_address(hostname: str) -> bool:
    """Return True if hostname is an IPv4 or IPv6 address."""

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _get_registered_domain(hostname: str) -> str:
    """
    Lightweight domain extraction.

    This intentionally avoids external dependencies such as tldextract.
    For advanced deployment, a Public Suffix List based implementation
    can be added.
    """

    if not hostname:
        return ""

    hostname = hostname.lower().strip(".")

    if _is_ip_address(hostname):
        return hostname

    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    # Basic handling for common two-level country-code domains.
    common_second_level = {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.in",
        "firm.in",
        "net.in",
        "org.in",
        "gen.in",
    }

    last_two = ".".join(parts[-2:])

    if last_two in common_second_level and len(parts) >= 3:
        return ".".join(parts[-3:])

    return last_two


def _calculate_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string."""

    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 3)


def _keyword_matches(text: str) -> list[str]:
    """Return suspicious keywords found in text."""

    text = text.lower()

    found = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text:
            found.append(keyword)

    return sorted(found)


def _brand_impersonation(hostname: str) -> list[str]:
    """
    Detect simple brand impersonation indicators.

    Example:
        paypal-security-example.com

    This is only a lexical indicator. It does not prove impersonation.
    """

    hostname = hostname.lower()

    detected = []

    for brand in BRAND_NAMES:
        if brand in hostname:
            registered_domain = _get_registered_domain(hostname)

            if brand not in registered_domain:
                detected.append(brand)

    return sorted(detected)


def _has_excessive_subdomains(hostname: str) -> bool:
    """Detect unusually deep subdomain structures."""

    if not hostname:
        return False

    labels = hostname.split(".")

    return len(labels) >= 5


def _has_suspicious_encoding(url: str) -> bool:
    """Detect excessive URL encoding or encoded control characters."""

    encoded_parts = re.findall(r"%[0-9a-fA-F]{2}", url)

    if len(encoded_parts) >= 5:
        return True

    decoded = unquote(url)

    control_chars = any(ord(char) < 32 for char in decoded)

    return control_chars


def _contains_dangerous_file(url_path: str) -> bool:
    """Detect potentially dangerous downloadable file extensions."""

    path = url_path.lower()

    return any(path.endswith(extension) for extension in DANGEROUS_FILE_EXTENSIONS)


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze_url(url: str) -> dict[str, Any]:
    """
    Analyze a URL for phishing indicators.

    Returns a stable JSON-serializable dictionary:

    {
        "url": "...",
        "is_valid": True,
        "risk_score": 65.0,
        "severity": "HIGH",
        "prediction": "PHISHING",
        "confidence": 0.65,
        "indicators": [...],
        "features": {...},
        "recommendation": "...",
    }

    No external network request is performed.
    """

    original_url = str(url).strip() if url is not None else ""

    if not original_url:
        return {
            "url": "",
            "is_valid": False,
            "risk_score": 0.0,
            "severity": "SAFE",
            "prediction": "INVALID_URL",
            "confidence": 1.0,
            "indicators": ["URL is empty."],
            "features": {},
            "recommendation": "Provide a valid HTTP or HTTPS URL.",
        }

    if len(original_url) > MAX_URL_LENGTH:
        return {
            "url": original_url[:MAX_URL_LENGTH],
            "is_valid": False,
            "risk_score": 70.0,
            "severity": "HIGH",
            "prediction": "SUSPICIOUS",
            "confidence": 0.85,
            "indicators": [
                f"URL exceeds maximum supported length of {MAX_URL_LENGTH} characters."
            ],
            "features": {
                "url_length": len(original_url),
            },
            "recommendation": "Do not open the URL until it is independently verified.",
        }

    normalized_url = _normalize_url(original_url)

    try:
        parsed = urlparse(normalized_url)
        hostname = (parsed.hostname or "").lower()
    except ValueError:
        return {
            "url": original_url,
            "is_valid": False,
            "risk_score": 70.0,
            "severity": "HIGH",
            "prediction": "INVALID_URL",
            "confidence": 0.90,
            "indicators": ["URL parsing failed."],
            "features": {},
            "recommendation": "Do not open the malformed URL.",
        }

    if not _is_valid_http_url(parsed):
        return {
            "url": original_url,
            "is_valid": False,
            "risk_score": 50.0,
            "severity": "MEDIUM",
            "prediction": "UNSUPPORTED_URL",
            "confidence": 0.90,
            "indicators": [
                "URL does not use HTTP or HTTPS or does not contain a hostname."
            ],
            "features": {
                "scheme": parsed.scheme,
                "hostname": hostname,
            },
            "recommendation": "Only analyze HTTP or HTTPS web URLs.",
        }

    # -----------------------------------------------------------------------
    # Feature extraction
    # -----------------------------------------------------------------------

    url_length = len(normalized_url)
    hostname_length = len(hostname)

    path = parsed.path or ""
    query = parsed.query or ""

    full_lower = normalized_url.lower()

    is_https = parsed.scheme.lower() == "https"
    is_ip = _is_ip_address(hostname)
    is_shortener = hostname in SHORTENER_DOMAINS

    suspicious_keywords = _keyword_matches(full_lower)
    brand_indicators = _brand_impersonation(hostname)

    subdomain_count = max(0, len(hostname.split(".")) - 2)

    special_characters = len(
        re.findall(r"[@!?=&%_\-]", normalized_url)
    )

    encoded_character_count = len(
        re.findall(r"%[0-9a-fA-F]{2}", normalized_url)
    )

    digit_count = sum(character.isdigit() for character in hostname)

    hyphen_count = hostname.count("-")

    entropy = _calculate_entropy(hostname)

    suspicious_tld = False

    if "." in hostname:
        tld = hostname.rsplit(".", 1)[-1]
        suspicious_tld = tld in HIGH_RISK_TLDS
    else:
        tld = ""

    dangerous_file = _contains_dangerous_file(path)

    has_at_symbol = "@" in normalized_url

    excessive_subdomains = _has_excessive_subdomains(hostname)

    suspicious_encoding = _has_suspicious_encoding(normalized_url)

    has_port = parsed.port is not None

    query_parameter_count = len(parse_qs(query, keep_blank_values=True))

    # -----------------------------------------------------------------------
    # Risk scoring
    # -----------------------------------------------------------------------

    score = 0.0
    indicators: list[str] = []

    def add_risk(points: float, reason: str) -> None:
        nonlocal score
        score += points
        indicators.append(reason)

    # 1. IP address instead of domain
    if is_ip:
        add_risk(
            25,
            "Hostname is an IP address instead of a normal domain.",
        )

    # 2. No HTTPS
    if not is_https:
        add_risk(
            8,
            "Connection does not use HTTPS.",
        )

    # Important:
    # HTTPS is not treated as proof of safety.

    # 3. Very long URL
    if url_length >= 200:
        add_risk(
            10,
            "URL is unusually long.",
        )
    elif url_length >= 120:
        add_risk(
            5,
            "URL is longer than typical web URLs.",
        )

    # 4. Suspicious keywords
    keyword_points = min(20, len(suspicious_keywords) * 4)

    if keyword_points:
        add_risk(
            keyword_points,
            "Suspicious security/account-related keywords detected: "
            + ", ".join(suspicious_keywords[:8])
            + ".",
        )

    # 5. URL shortener
    if is_shortener:
        add_risk(
            12,
            "URL uses a known URL-shortening service; final destination should be inspected.",
        )

    # 6. @ symbol
    if has_at_symbol:
        add_risk(
            18,
            "URL contains '@', which can be abused to disguise the actual hostname.",
        )

    # 7. Excessive subdomains
    if excessive_subdomains:
        add_risk(
            12,
            "URL contains an unusually deep subdomain structure.",
        )

    # 8. Brand impersonation
    if brand_indicators:
        add_risk(
            min(25, len(brand_indicators) * 12),
            "Possible brand impersonation indicator detected: "
            + ", ".join(brand_indicators)
            + ".",
        )

    # 9. Suspicious TLD
    if suspicious_tld:
        add_risk(
            8,
            f"Domain uses a higher-risk TLD: .{tld}.",
        )

    # 10. Suspicious encoding
    if suspicious_encoding:
        add_risk(
            10,
            "URL contains unusually heavy or suspicious encoding.",
        )

    # 11. Many special characters
    if special_characters >= 15:
        add_risk(
            10,
            "URL contains an unusually high number of special characters.",
        )
    elif special_characters >= 8:
        add_risk(
            5,
            "URL contains many special characters.",
        )

    # 12. High hostname entropy
    if entropy >= 4.0 and hostname_length >= 20:
        add_risk(
            8,
            "Hostname has high character randomness/entropy.",
        )

    # 13. Excessive digits
    if digit_count >= 6:
        add_risk(
            6,
            "Hostname contains an unusually high number of digits.",
        )

    # 14. Multiple hyphens
    if hyphen_count >= 3:
        add_risk(
            5,
            "Hostname contains multiple hyphens.",
        )

    # 15. Dangerous file
    if dangerous_file:
        add_risk(
            15,
            "URL path points to a potentially dangerous executable/script file.",
        )

    # 16. Explicit suspicious query volume
    if query_parameter_count >= 8:
        add_risk(
            5,
            "URL contains an unusually large number of query parameters.",
        )

    # 17. Non-standard port
    if has_port and parsed.port not in {80, 443}:
        add_risk(
            5,
            "URL uses a non-standard web port.",
        )

    # -----------------------------------------------------------------------
    # Additional correlations
    # -----------------------------------------------------------------------

    # Login/payment + IP is more suspicious than either signal alone.
    if is_ip and suspicious_keywords:
        add_risk(
            10,
            "Account/security-related keywords are combined with an IP-based host.",
        )

    # Brand impersonation + login/verification is particularly suspicious.
    if brand_indicators and suspicious_keywords:
        add_risk(
            12,
            "Possible brand impersonation is combined with account/security language.",
        )

    # Shortener + suspicious keywords deserves extra attention.
    if is_shortener and suspicious_keywords:
        add_risk(
            6,
            "URL shortener is combined with suspicious account/security language.",
        )

    score = _clamp_score(score)

    severity = _get_severity(score)

    # -----------------------------------------------------------------------
    # Prediction and confidence
    # -----------------------------------------------------------------------

    if score >= 80:
        prediction = "PHISHING"
    elif score >= 60:
        prediction = "LIKELY_PHISHING"
    elif score >= 40:
        prediction = "SUSPICIOUS"
    elif score >= 20:
        prediction = "LOW_RISK"
    else:
        prediction = "SAFE"

    # Confidence here represents confidence of the rule-based classification,
    # not probability that the URL is malicious.
    if score >= 80:
        confidence = 0.90
    elif score >= 60:
        confidence = 0.80
    elif score >= 40:
        confidence = 0.70
    elif score >= 20:
        confidence = 0.60
    else:
        confidence = 0.55

    # -----------------------------------------------------------------------
    # Recommendation
    # -----------------------------------------------------------------------

    if severity == "CRITICAL":
        recommendation = (
            "Block or quarantine the URL and investigate the destination "
            "using reputation, redirect and page-behaviour analysis."
        )
    elif severity == "HIGH":
        recommendation = (
            "Do not open the URL. Block or quarantine it and perform "
            "additional reputation and destination analysis."
        )
    elif severity == "MEDIUM":
        recommendation = (
            "Treat the URL with caution and perform additional domain, "
            "redirect and page-behaviour checks."
        )
    elif severity == "LOW":
        recommendation = (
            "No strong phishing evidence was found, but continue monitoring "
            "and verify the destination before sensitive actions."
        )
    else:
        recommendation = (
            "No major phishing indicators were detected by the current "
            "rule-based analysis."
        )

    return {
        "url": original_url,
        "normalized_url": normalized_url,
        "is_valid": True,
        "risk_score": score,
        "severity": severity,
        "prediction": prediction,
        "confidence": confidence,
        "indicators": indicators,
        "features": {
            "scheme": parsed.scheme.lower(),
            "hostname": hostname,
            "registered_domain": _get_registered_domain(hostname),
            "url_length": url_length,
            "hostname_length": hostname_length,
            "https": is_https,
            "ip_address_host": is_ip,
            "url_shortener": is_shortener,
            "suspicious_keywords": suspicious_keywords,
            "brand_impersonation": brand_indicators,
            "suspicious_tld": suspicious_tld,
            "tld": tld,
            "subdomain_count": subdomain_count,
            "excessive_subdomains": excessive_subdomains,
            "special_character_count": special_characters,
            "encoded_character_count": encoded_character_count,
            "suspicious_encoding": suspicious_encoding,
            "hostname_entropy": entropy,
            "hostname_digit_count": digit_count,
            "hostname_hyphen_count": hyphen_count,
            "has_at_symbol": has_at_symbol,
            "query_parameter_count": query_parameter_count,
            "non_standard_port": (
                has_port and parsed.port not in {80, 443}
            ),
            "dangerous_file_extension": dangerous_file,
        },
        "recommendation": recommendation,
    }


# ---------------------------------------------------------------------------
# Compatibility wrapper
# ---------------------------------------------------------------------------

def analyze_phishing_url(url: str) -> dict[str, Any]:
    """
    Compatibility alias for the application layer.

    Use this if the Django phishing module wants a descriptive function name.
    """

    return analyze_url(url)


def predict(url: str) -> dict[str, Any]:
    """
    Short compatibility API for future AI/model integration.
    """

    return analyze_url(url)