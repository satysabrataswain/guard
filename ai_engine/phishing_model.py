

import ipaddress
import math
import re
from collections import Counter
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .url_redirect import resolve_redirect_chain
from .google_safe_browsing import check_url_with_google


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

# Domains that are commonly trusted. Unknown domains are treated as
# unverified, not automatically malicious.
TRUSTED_DOMAINS = {
    "google.com", "google.co.in", "microsoft.com", "office.com",
    "outlook.com", "apple.com", "amazon.com", "amazon.in",
    "github.com", "linkedin.com", "facebook.com", "instagram.com",
    "youtube.com", "zoom.us", "outskill.com", "imit.ac.in",
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


def _is_trusted_domain(hostname: str) -> bool:
    """Return True when hostname belongs to a known trusted domain."""

    hostname = (hostname or "").lower().strip(".")
    if not hostname:
        return False

    return (
        hostname in TRUSTED_DOMAINS
        or any(hostname.endswith("." + domain) for domain in TRUSTED_DOMAINS)
    )


def _build_simple_explanation(
    prediction: str,
    is_shortener: bool,
    redirect_count: int,
    redirect_destination_changed: bool,
    destination_score: float,
    redirect_error: str,
    suspicious_keywords: list[str],
    brand_indicators: list[str],
    is_ip: bool,
    suspicious_tld: bool,
    dangerous_file: bool,
    google_matched: bool = False,
    google_checked: bool = False,
) -> str:
    """Create a short, user-friendly URL explanation."""

    if google_matched:
        return (
            "Google Safe Browsing reported this link as unsafe. "
            "Do not open it or enter passwords, OTPs, or financial information."
        )

    if prediction in {"PHISHING", "LIKELY_PHISHING"}:
        reasons = []

        if is_ip:
            reasons.append("uses an IP address instead of a normal domain")
        if brand_indicators:
            reasons.append("may be impersonating a known brand")
        if suspicious_keywords:
            reasons.append("contains account or security-related terms")
        if is_shortener:
            reasons.append("uses a shortened link")
        if redirect_destination_changed:
            reasons.append("redirects to another website")
        if suspicious_tld:
            reasons.append("uses a higher-risk domain extension")
        if dangerous_file:
            reasons.append("points to a potentially dangerous file")

        if len(reasons) > 2:
            reason_text = ", ".join(reasons[:-1]) + f", and {reasons[-1]}"
        elif len(reasons) == 2:
            reason_text = f"{reasons[0]} and {reasons[1]}"
        elif reasons:
            reason_text = reasons[0]
        else:
            reason_text = "shows several suspicious characteristics"

        return (
            f"This link looks suspicious because it {reason_text}. "
            "Avoid opening it or entering personal information."
        )

    if prediction == "SUSPICIOUS":
        if is_shortener and redirect_destination_changed:
            return (
                "This shortened link redirects to another website. "
                "The destination should be verified before opening it."
            )

        if redirect_error:
            return (
                "This link could not be fully verified. "
                "Check the destination before opening it."
            )

        if destination_score >= 40:
            return (
                "The link redirects to a destination with suspicious signs. "
                "Avoid opening it until the destination is verified."
            )

        return (
            "This link has some suspicious characteristics. "
            "Verify the website before opening it."
        )

    if prediction == "LOW_RISK":
        if redirect_error:
            return (
                "The link could not be fully verified. "
                "It is not confirmed to be unsafe, but check the destination "
                "before opening it."
            )

        if is_shortener:
            return (
                "This is a shortened link. No strong phishing signs were found, "
                "but verify the final destination before opening it."
            )

        return (
            "No strong phishing signs were detected. "
            "Still verify the website before entering sensitive information."
        )

    return (
        "No major phishing signs were detected in this link. "
        "Always check the website address before entering sensitive information."
    )


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze_url(
    url: str,
    *,
    resolve_redirects: bool = True,
) -> dict[str, Any]:
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

    By default, HTTP/HTTPS redirect chains are inspected. Redirect targets
    are validated before each request and private/local destinations are
    blocked. Set resolve_redirects=False for offline-only analysis.
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
    # Redirect / shortener inspection
    # -----------------------------------------------------------------------

    redirect_info: dict[str, Any] = {
        "enabled": False,
        "resolved": False,
        "original_url": original_url,
        "final_url": normalized_url,
        "redirect_chain": [normalized_url],
        "redirect_count": 0,
        "status_codes": [],
        "shortener_detected": False,
        "error": "",
    }

    if resolve_redirects:
        redirect_info = resolve_redirect_chain(normalized_url)

    final_url = str(
        redirect_info.get(
            "final_url",
            normalized_url,
        )
        or normalized_url
    )

    try:
        final_parsed = urlparse(final_url)
        final_hostname = (final_parsed.hostname or "").lower()
    except ValueError:
        final_parsed = parsed
        final_hostname = hostname

    redirect_count = int(
        redirect_info.get(
            "redirect_count",
            0,
        )
        or 0
    )

    # -----------------------------------------------------------------------
    # Google Safe Browsing reputation check
    # -----------------------------------------------------------------------

    google_original = check_url_with_google(normalized_url)
    google_final = {}

    if final_url and final_url != normalized_url:
        google_final = check_url_with_google(final_url)

    google_matched = bool(
        google_original.get("matched")
        or google_final.get("matched")
    )

    google_checked = bool(
        google_original.get("checked")
        or google_final.get("checked")
    )

    google_errors = [
        str(item.get("error"))
        for item in (google_original, google_final)
        if item.get("error")
    ]

    google_matches = []
    for source in (google_original, google_final):
        for match in source.get("matches", []) or []:
            if match not in google_matches:
                google_matches.append(match)

    destination_result: dict[str, Any] = {}

    if (
        redirect_count > 0
        and final_url
        and final_url != normalized_url
    ):
        # Analyze the final destination without resolving it again.
        destination_result = analyze_url(
            final_url,
            resolve_redirects=False,
        )

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
    is_shortener = (
        hostname in SHORTENER_DOMAINS
        or hostname.removeprefix("www.") in SHORTENER_DOMAINS
    )

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

    # Google Safe Browsing is an external reputation signal. A confirmed
    # match is treated as a strong indicator. An API failure is NOT treated
    # as proof that the URL is malicious.
    if google_matched:
        add_risk(
            100,
            "Google Safe Browsing reported this URL as unsafe.",
        )

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
            "URL uses a known URL-shortening service; final destination was inspected.",
        )

    # 6. Redirect chain
    if redirect_count == 1:
        add_risk(
            4,
            "URL redirects to another destination.",
        )
    elif redirect_count >= 2:
        add_risk(
            min(14, 4 + ((redirect_count - 1) * 3)),
            f"URL uses a redirect chain with {redirect_count} hop(s).",
        )

    redirect_error = str(redirect_info.get("error") or "").strip()

    if redirect_error:
        indicators.append(
            "The link could not be fully verified because destination inspection failed."
        )
        add_risk(
            8,
            "Destination could not be fully verified.",
        )

    destination_score = _clamp_score(
        destination_result.get(
            "risk_score",
            0,
        )
    ) if destination_result else 0.0

    if destination_score >= 40:
        add_risk(
            min(30, round(destination_score * 0.40, 2)),
            "Final redirect destination contains phishing-risk indicators.",
        )

    # 7. @ symbol
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

    # A redirect from a shortener to a different registered domain is a useful
    # contextual signal. It is not automatically malicious.
    original_registered = _get_registered_domain(hostname)
    final_registered = _get_registered_domain(final_hostname)

    redirect_destination_changed = bool(
        redirect_count > 0
        and original_registered
        and final_registered
        and original_registered != final_registered
    )

    final_domain_trusted = _is_trusted_domain(final_hostname)

    if redirect_destination_changed:
        if is_shortener and not final_domain_trusted:
            add_risk(
                18,
                "Shortened link redirects to a different unverified website.",
            )
        else:
            add_risk(
                4,
                "Link redirects to a different website.",
            )

    if final_domain_trusted:
        indicators.append(
            "Final destination belongs to a recognized trusted domain."
        )

    if google_checked and not google_matched:
        indicators.append("Google Safe Browsing found no known threat match.")
    elif not google_checked and google_errors:
        indicators.append(
            "Google Safe Browsing could not verify the URL; this does not mean the URL is unsafe."
        )

    score = _clamp_score(score)

    severity = _get_severity(score)

    # -----------------------------------------------------------------------
    # Prediction and confidence
    # -----------------------------------------------------------------------

    if google_matched:
        prediction = "PHISHING"
    elif score >= 80:
        prediction = "PHISHING"
    elif score >= 60:
        prediction = "LIKELY_PHISHING"
    elif (
        is_shortener
        and redirect_destination_changed
        and not final_domain_trusted
    ):
        prediction = "SUSPICIOUS"
    elif score >= 40:
        prediction = "SUSPICIOUS"
    elif score >= 20:
        prediction = "LOW_RISK"
    else:
        prediction = "SAFE"

    # Confidence here represents confidence of the rule-based classification,
    # not probability that the URL is malicious.
    if google_matched:
        confidence = 0.98
    elif score >= 80:
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
    # Simple explanation
    # -----------------------------------------------------------------------

    explanation = _build_simple_explanation(
        prediction=prediction,
        is_shortener=is_shortener,
        redirect_count=redirect_count,
        redirect_destination_changed=redirect_destination_changed,
        destination_score=destination_score,
        redirect_error=redirect_error,
        suspicious_keywords=suspicious_keywords,
        brand_indicators=brand_indicators,
        is_ip=is_ip,
        suspicious_tld=suspicious_tld,
        dangerous_file=dangerous_file,
        google_matched=google_matched,
        google_checked=google_checked,
    )

    # -----------------------------------------------------------------------
    # Recommendation
    # -----------------------------------------------------------------------

    if prediction in {"PHISHING", "LIKELY_PHISHING"}:
        recommendation = (
            "Do not open the link. Verify the sender and destination "
            "through an independent source."
        )
    elif prediction == "SUSPICIOUS":
        recommendation = (
            "Verify the destination before opening the link "
            "or entering personal information."
        )
    elif severity == "CRITICAL":
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
            "redirects_enabled": bool(resolve_redirects),
            "redirect_resolved": bool(redirect_info.get("resolved", False)),
            "redirect_count": redirect_count,
            "redirect_chain": redirect_info.get("redirect_chain", []),
            "redirect_status_codes": redirect_info.get("status_codes", []),
            "redirect_error": redirect_info.get("error", ""),
            "final_url": final_url,
            "landing_page_url": final_url,
            "landing_page_hostname": final_hostname,
            "final_hostname": final_hostname,
            "final_registered_domain": final_registered,
            "final_domain_trusted": final_domain_trusted,
            "redirect_destination_changed": redirect_destination_changed,
            "destination_unverified": bool(
                redirect_error
                or (
                    final_hostname
                    and not final_domain_trusted
                )
            ),
            "google_safe_browsing": {
                "provider": "Google Safe Browsing",
                "checked": google_checked,
                "matched": google_matched,
                "safe": (
                    False
                    if google_matched
                    else True
                    if google_checked
                    else None
                ),
                "original_url": google_original,
                "final_url": google_final,
                "matches": google_matches,
                "errors": google_errors,
            },
            "destination_risk_score": destination_score,
            "destination_severity": destination_result.get(
                "severity",
                "SAFE",
            ) if destination_result else "SAFE",
            "destination_prediction": destination_result.get(
                "prediction",
                "UNKNOWN",
            ) if destination_result else "UNKNOWN",
            "destination_indicators": destination_result.get(
                "indicators",
                [],
            ) if destination_result else [],
        },
        "explanation": explanation,
        "recommendation": recommendation,
    }


# ---------------------------------------------------------------------------
# Compatibility wrapper
# ---------------------------------------------------------------------------

def analyze_phishing_url(
    url: str,
    *,
    resolve_redirects: bool = True,
) -> dict[str, Any]:
    """
    Compatibility alias for the application layer.

    Use this if the Django phishing module wants a descriptive function name.
    """

    return analyze_url(
        url,
        resolve_redirects=resolve_redirects,
    )


def predict(url: str) -> dict[str, Any]:
    """
    Short compatibility API for future AI/model integration.
    """

    return analyze_url(url)