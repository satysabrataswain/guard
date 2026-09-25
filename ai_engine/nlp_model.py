

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


# ============================================================================
# CONFIGURATION
# ============================================================================

MAX_TEXT_LENGTH = 50_000


# ============================================================================
# KEYWORD GROUPS
# ============================================================================

URGENT_KEYWORDS = {
    "urgent",
    "immediately",
    "asap",
    "now",
    "hurry",
    "quickly",
    "action required",
    "act now",
    "final warning",
    "last warning",
    "expires",
    "deadline",
}


CREDENTIAL_KEYWORDS = {
    "password",
    "username",
    "user id",
    "login",
    "sign in",
    "signin",
    "credential",
    "credentials",
    "otp",
    "one time password",
    "verification code",
    "security code",
    "pin",
    "passcode",
}


FINANCIAL_KEYWORDS = {
    "bank",
    "bank account",
    "credit card",
    "debit card",
    "card number",
    "account number",
    "upi",
    "payment",
    "transaction",
    "refund",
    "invoice",
    "money",
    "transfer",
    "wallet",
    "crypto",
    "cryptocurrency",
    "gift card",
}


THREAT_KEYWORDS = {
    "suspended",
    "blocked",
    "locked",
    "terminated",
    "disabled",
    "legal action",
    "police",
    "arrest",
    "penalty",
    "fine",
    "security alert",
    "unauthorized",
    "breach",
}


TRUST_KEYWORDS = {
    "official",
    "support",
    "administrator",
    "admin",
    "security team",
    "customer service",
    "technical support",
    "helpdesk",
}


REQUEST_KEYWORDS = {
    "click",
    "open",
    "verify",
    "confirm",
    "update",
    "reset",
    "download",
    "install",
    "reply",
    "send",
    "share",
    "provide",
    "submit",
}


# ============================================================================
# PROMOTIONAL / MARKETING KEYWORDS
# ============================================================================

PROMOTIONAL_KEYWORDS = {
    "promotion",
    "promotional",
    "offer",
    "special offer",
    "discount",
    "sale",
    "deal",
    "deals",
    "limited offer",
    "exclusive offer",
    "free",
    "coupon",
    "voucher",
    "newsletter",
    "marketing",
    "campaign",
    "announcement",
    "subscribe",
    "unsubscribe",
    "subscription",
}


EVENT_KEYWORDS = {
    "event",
    "webinar",
    "workshop",
    "seminar",
    "conference",
    "session",
    "training",
    "masterclass",
    "mastermind",
    "live session",
    "online session",
    "meeting",
    "bootcamp",
}


REGISTRATION_KEYWORDS = {
    "register",
    "registration",
    "register here",
    "sign up",
    "signup",
    "join us",
    "join now",
    "book your seat",
    "reserve your seat",
    "enroll",
    "enrollment",
}




# ============================================================================
# SPAM / UNSOLICITED MESSAGE KEYWORDS
# ============================================================================

SPAM_KEYWORDS = {
    "you have won",
    "you are a winner",
    "winner",
    "claim your prize",
    "claim prize",
    "lottery",
    "jackpot",
    "cash prize",
    "prize money",
    "congratulations you won",
    "make money fast",
    "earn money fast",
    "easy money",
    "work from home",
    "guaranteed income",
    "double your money",
    "investment opportunity",
    "free gift",
    "free money",
    "click here now",
    "act now",
    "exclusive deal",
    "limited time",
    "risk free",
    "no obligation",
}


PROMOTIONAL_CTA_KEYWORDS = {
    "learn more",
    "get started",
    "claim",
    "shop now",
    "buy now",
    "view offer",
    "view details",
    "read more",
    "discover",
    "attend",
    "save your seat",
    "reserve",
}


SUSPICIOUS_ATTACHMENT_EXTENSIONS = {
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
    ".hta",
    ".zip",
    ".rar",
}


# ============================================================================
# URL / EMAIL PATTERNS
# ============================================================================

URL_PATTERN = re.compile(
    r"(?:https?://|www\.)[^\s<>\"]+",
    re.IGNORECASE,
)


EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)


OTP_PATTERN = re.compile(
    r"\b(?:otp|one[- ]time password|verification code|security code)\b",
    re.IGNORECASE,
)


MONEY_PATTERN = re.compile(
    r"(?:₹|\$|€|£)\s?\d+(?:[.,]\d+)*"
    r"|\b\d+(?:[.,]\d+)?\s?(?:rupees|rs|usd|dollars|euros|pounds)\b",
    re.IGNORECASE,
)


IP_URL_PATTERN = re.compile(
    r"^(?:https?://)?"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?::\d+)?(?:/|$)",
    re.IGNORECASE,
)


# ============================================================================
# BASIC TRUSTED DOMAINS
# ============================================================================
#
# This is intentionally a small list.
# A domain not present here is treated as UNVERIFIED, not automatically
# malicious. Promotional + unverified external link can therefore be
# classified as SUSPICIOUS, while stronger phishing signals still have
# priority.
#

TRUSTED_DOMAINS = {
    "google.com",
    "google.co.in",
    "microsoft.com",
    "office.com",
    "outlook.com",
    "linkedin.com",
    "github.com",
    "apple.com",
    "amazon.com",
    "amazon.in",
    "facebook.com",
    "instagram.com",
    "youtube.com",
    "zoom.us",
    "meet.google.com",
    "outskill.com",
}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _clamp_score(score: float) -> float:
    """Keep risk score between 0 and 100."""

    return round(max(0.0, min(100.0, float(score))), 2)


def _get_severity(score: float) -> str:
    """Convert numerical score to platform severity."""

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    if score >= 20:
        return "LOW"

    return "SAFE"


def _find_keywords(text: str, keywords: set[str]) -> list[str]:
    """Find configured keywords or phrases in text."""

    text_lower = text.lower()

    found = []

    for keyword in keywords:
        if keyword.lower() in text_lower:
            found.append(keyword)

    return sorted(found)


def _extract_urls(text: str) -> list[str]:
    """Extract HTTP/HTTPS/www URLs."""

    urls = URL_PATTERN.findall(text)

    cleaned = []

    for url in urls:
        cleaned_url = url.rstrip(".,;:!?)]}>\"'")
        if cleaned_url:
            cleaned.append(cleaned_url)

    return cleaned


def _extract_emails(text: str) -> list[str]:
    """Extract email addresses."""

    return EMAIL_PATTERN.findall(text)


def _detect_suspicious_attachments(text: str) -> list[str]:
    """
    Detect potentially dangerous attachment filenames.

    Normal domains such as example.com or microsoft.com are not treated
    as .com attachments.
    """

    found = []

    extension_pattern = "|".join(
        re.escape(extension)
        for extension in SUSPICIOUS_ATTACHMENT_EXTENSIONS
    )

    pattern = re.compile(
        rf"(?<![\w.])"
        rf"[\w\s\-_()]+\.(?:"
        rf"{extension_pattern.replace(r'\\.', '')}"
        rf")"
        rf"(?![\w.])",
        re.IGNORECASE,
    )

    matches = pattern.findall(text)

    for match in matches:
        match_lower = match.lower()

        for extension in SUSPICIOUS_ATTACHMENT_EXTENSIONS:
            if match_lower.endswith(extension):
                if extension not in found:
                    found.append(extension)

    return sorted(found)


def _detect_excessive_caps(text: str) -> bool:
    """Detect unusually high uppercase usage."""

    letters = [
        character
        for character in text
        if character.isalpha()
    ]

    if len(letters) < 20:
        return False

    uppercase = sum(
        1
        for character in letters
        if character.isupper()
    )

    return (uppercase / len(letters)) >= 0.65


def _detect_excessive_exclamation(text: str) -> bool:
    """Detect repeated exclamation marks."""

    return bool(
        re.search(r"!{3,}", text)
    )


def _detect_obfuscation(text: str) -> bool:
    """
    Detect deliberate obfuscation of security-related words.

    Examples:
        P@ssw0rd
        L0g1n
        V3r1fy
        Secur1ty
    """

    patterns = [
        r"p[@]ssw[o0]rd",
        r"l[o0]g[i1]n",
        r"v[e3]r[i1]fy",
        r"[@]cc[o0]unt",
        r"secur[i1]ty",
    ]

    return any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in patterns
    )


def _detect_html_or_script(text: str) -> bool:
    """Detect HTML/script-like content."""

    patterns = [
        r"<script\b",
        r"javascript:",
        r"<iframe\b",
        r"onerror\s*=",
        r"onclick\s*=",
    ]

    return any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in patterns
    )


# ============================================================================
# PROMOTIONAL ANALYSIS
# ============================================================================

def _detect_promotional_content(
    promotional_keywords: list[str],
    event_keywords: list[str],
    registration_keywords: list[str],
    promotional_cta_keywords: list[str],
    text: str,
) -> dict[str, Any]:
    """
    Detect marketing, event, webinar and promotional content.

    This does not mean the message is malicious.
    It is only a content category.
    """

    unsubscribe_detected = "unsubscribe" in text.lower()

    marketing_score = 0

    marketing_score += len(promotional_keywords) * 2
    marketing_score += len(event_keywords) * 2
    marketing_score += len(registration_keywords) * 2
    marketing_score += len(promotional_cta_keywords) * 1

    if unsubscribe_detected:
        marketing_score += 3

    detected = (
        marketing_score >= 3
        or len(event_keywords) >= 1
        or len(registration_keywords) >= 1
        or unsubscribe_detected
    )

    if event_keywords:
        category = "EVENT"
    elif registration_keywords:
        category = "REGISTRATION"
    elif promotional_keywords:
        category = "MARKETING"
    elif unsubscribe_detected:
        category = "NEWSLETTER"
    else:
        category = "GENERAL"

    return {
        "detected": detected,
        "category": category if detected else None,
        "marketing_score": min(marketing_score, 100),
        "promotional_keywords": promotional_keywords,
        "event_keywords": event_keywords,
        "registration_keywords": registration_keywords,
        "promotional_cta_keywords": promotional_cta_keywords,
        "unsubscribe_detected": unsubscribe_detected,
    }


# ============================================================================
# SPAM ANALYSIS
# ============================================================================

def _detect_spam_content(
    spam_keywords: list[str],
    urls: list[str],
    suspicious_attachments: list[str],
    excessive_caps: bool,
    excessive_exclamation: bool,
    text: str,
) -> dict[str, Any]:
    """Detect common unsolicited/spam patterns without treating marketing as spam by default."""

    score = 0
    reasons: list[str] = []

    score += min(60, len(spam_keywords) * 8)
    if spam_keywords:
        reasons.append("Spam-like phrases detected.")

    if excessive_caps:
        score += 8
        reasons.append("Unusually high uppercase usage.")

    if excessive_exclamation:
        score += 8
        reasons.append("Repeated exclamation marks.")

    if len(urls) >= 4:
        score += 10
        reasons.append("Message contains many links.")

    if suspicious_attachments:
        score += min(20, len(suspicious_attachments) * 8)
        reasons.append("Potentially risky attachment names detected.")

    # Very short messages made almost entirely of promotional bait are more
    # likely to be spam than normal transactional mail.
    word_count = len(re.findall(r"\b\w+\b", text))
    if word_count <= 12 and (spam_keywords or len(urls) >= 2):
        score += 8
        reasons.append("Very short message contains unsolicited-action signals.")

    score = min(score, 100)

    return {
        "detected": score >= 20,
        "score": score,
        "keywords": spam_keywords,
        "reasons": reasons,
    }


# ============================================================================
# URL ANALYSIS
# ============================================================================

def _analyze_url(url: str) -> dict[str, Any]:
    """
    Perform lightweight offline URL analysis.

    This does NOT visit the URL.
    """

    original_url = url

    if not re.match(r"^https?://", url, re.IGNORECASE):
        parse_target = "http://" + url
    else:
        parse_target = url

    try:
        parsed = urlparse(parse_target)
    except Exception:
        return {
            "url": original_url,
            "domain": "",
            "scheme": "",
            "is_secure": False,
            "is_ip_address": False,
            "is_shortener": False,
            "has_suspicious_terms": True,
            "is_trusted": False,
            "is_unverified": True,
            "suspicious": True,
            "reasons": ["URL could not be safely parsed."],
        }

    domain = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()

    reasons = []

    is_ip_address = bool(
        IP_URL_PATTERN.match(domain)
    )

    suspicious_domain_terms = {
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "credential",
        "confirm",
        "wallet",
        "payment",
        "bank",
        "signin",
    }

    shortener_domains = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "ow.ly",
        "cutt.ly",
        "rb.gy",
        "shorturl.at",
    }

    domain_parts = domain.split(".")

    is_shortener = domain in shortener_domains

    has_suspicious_terms = any(
        term in domain.lower()
        for term in suspicious_domain_terms
    )

    trusted = (
        domain in TRUSTED_DOMAINS
        or any(
            domain.endswith("." + trusted_domain)
            for trusted_domain in TRUSTED_DOMAINS
        )
    )

    is_unverified = bool(domain) and not trusted

    if is_ip_address:
        reasons.append("Link uses an IP address instead of a normal domain.")

    if is_shortener:
        reasons.append("Link uses a URL-shortening service.")

    if has_suspicious_terms:
        reasons.append(
            "Link contains security or account-related words."
        )

    if len(domain_parts) >= 4:
        reasons.append("Link uses a deeply nested domain.")

    if scheme != "https":
        reasons.append("Link does not use HTTPS.")

    suspicious = bool(
        is_ip_address
        or is_shortener
        or has_suspicious_terms
        or len(domain_parts) >= 4
        or scheme != "https"
    )

    return {
        "url": original_url,
        "domain": domain,
        "scheme": scheme,
        "is_secure": scheme == "https",
        "is_ip_address": is_ip_address,
        "is_shortener": is_shortener,
        "has_suspicious_terms": has_suspicious_terms,
        "is_trusted": trusted,
        "is_unverified": is_unverified,
        "suspicious": suspicious,
        "reasons": reasons,
    }


def _analyze_urls(urls: list[str]) -> dict[str, Any]:
    """Analyze all URLs found in the message."""

    details = [
        _analyze_url(url)
        for url in urls
    ]

    suspicious_urls = [
        item
        for item in details
        if item["suspicious"]
    ]

    unverified_urls = [
        item
        for item in details
        if item["is_unverified"]
    ]

    trusted_urls = [
        item
        for item in details
        if item["is_trusted"]
    ]

    return {
        "count": len(urls),
        "details": details,
        "suspicious_count": len(suspicious_urls),
        "unverified_count": len(unverified_urls),
        "trusted_count": len(trusted_urls),
        "suspicious_urls": [
            item["url"]
            for item in suspicious_urls
        ],
        "unverified_urls": [
            item["url"]
            for item in unverified_urls
        ],
        "trusted_urls": [
            item["url"]
            for item in trusted_urls
        ],
    }


# ============================================================================
# SIMPLE EXPLANATION
# ============================================================================

def _build_simple_explanation(
    prediction: str,
    promotional: dict[str, Any],
    url_analysis: dict[str, Any],
    urgent_keywords: list[str],
    credential_keywords: list[str],
    financial_keywords: list[str],
    threat_keywords: list[str],
    request_keywords: list[str],
    contains_otp_request: bool,
    suspicious_attachments: list[str],
    spam: dict[str, Any] | None = None,
) -> str:
    """
    Generate a short, user-friendly explanation.

    This intentionally avoids exposing the internal scoring/rule details
    to the end user.
    """

    if spam is None:
        spam = {}

    # ------------------------------------------------------------------
    # PHISHING
    # ------------------------------------------------------------------

    if prediction in {
        "PHISHING",
        "LIKELY_PHISHING",
    }:
        reasons = []

        if urgent_keywords:
            reasons.append("uses urgent language")

        if credential_keywords:
            reasons.append("asks for sensitive information")

        if financial_keywords:
            reasons.append("mentions financial or payment information")

        if threat_keywords:
            reasons.append("uses alarming or threatening language")

        if request_keywords:
            reasons.append("asks you to take an action")

        if url_analysis["count"] > 0:
            reasons.append("contains a web link")

        if contains_otp_request:
            reasons.append("mentions an OTP or security code")

        if suspicious_attachments:
            reasons.append("contains a potentially dangerous attachment")

        if reasons:
            if len(reasons) == 1:
                reason_text = reasons[0]
            elif len(reasons) == 2:
                reason_text = f"{reasons[0]} and {reasons[1]}"
            else:
                reason_text = (
                    ", ".join(reasons[:-1])
                    + f", and {reasons[-1]}"
                )

            return (
                "This email looks like a phishing attempt because it "
                f"{reason_text}. "
                "Do not click suspicious links or share your password, "
                "OTP, or other personal information."
            )

        return (
            "This email shows several signs of a possible phishing attack. "
            "Avoid clicking links or sharing sensitive information."
        )

    # ------------------------------------------------------------------
    # SUSPICIOUS PROMOTIONAL EMAIL
    # ------------------------------------------------------------------

    if prediction == "SUSPICIOUS" and promotional["detected"]:
        if url_analysis["suspicious_count"] > 0:
            return (
                "This looks like a promotional or event email, "
                "but one or more links look suspicious. "
                "Verify the sender and link before opening it."
            )

        if url_analysis["unverified_count"] > 0:
            return (
                "This looks like a promotional or event email, "
                "but it contains an unverified link. "
                "Check the sender and destination before opening it."
            )

        return (
            "This message contains promotional or event content "
            "with some suspicious signs. Verify the sender before taking action."
        )

    # ------------------------------------------------------------------
    # SPAM
    # ------------------------------------------------------------------

    if prediction == "SPAM":
        reasons = []

        if spam.get("keywords"):
            reasons.append("contains common spam phrases")

        if url_analysis["count"] >= 4:
            reasons.append("contains many links")

        if suspicious_attachments:
            reasons.append("contains potentially risky attachment names")

        if reasons:
            return (
                "This message shows common spam patterns because it "
                + ", ".join(reasons)
                + ". Avoid clicking links or downloading unexpected files."
            )

        return (
            "This message shows common unsolicited-message patterns. "
            "Treat unexpected links and offers carefully."
        )

    # ------------------------------------------------------------------
    # PROMOTIONAL
    # ------------------------------------------------------------------

    if prediction == "PROMOTIONAL":
        category = promotional.get("category")

        if category == "EVENT":
            return (
                "This appears to be an event or webinar email. "
                "It does not show major phishing signs."
            )

        if category == "REGISTRATION":
            return (
                "This appears to be a registration or promotional email. "
                "It does not show major phishing signs."
            )

        if category == "NEWSLETTER":
            return (
                "This appears to be a newsletter or marketing email. "
                "It does not show major phishing signs."
            )

        return (
            "This appears to be a promotional or marketing email. "
            "No major phishing signs were detected."
        )

    # ------------------------------------------------------------------
    # LOW RISK
    # ------------------------------------------------------------------

    if prediction == "LOW_RISK":
        return (
            "This message has a few low-risk indicators, "
            "but no strong signs of phishing were detected. "
            "Verify unexpected requests before taking action."
        )

    # ------------------------------------------------------------------
    # SAFE
    # ------------------------------------------------------------------

    return (
        "No major phishing signs were detected in this message. "
        "Continue to be careful with unexpected links and requests."
    )


# ============================================================================
# MAIN NLP ANALYSIS
# ============================================================================

def analyze_text(
    text: str,
    text_type: str = "message",
) -> dict[str, Any]:
    """
    Analyze email/message text for phishing, social engineering,
    and promotional content.

    Returns:
        risk_score
        severity
        prediction
        confidence
        indicators
        features
        recommendation
        explanation

    No external network request is performed.
    """

    if text is None:
        text = ""

    text = str(text)

    # =========================================================================
    # EMPTY INPUT
    # =========================================================================

    if not text.strip():
        return {
            "text_type": text_type,
            "is_valid": False,
            "risk_score": 0.0,
            "severity": "SAFE",
            "prediction": "EMPTY_TEXT",
            "confidence": 1.0,
            "indicators": [
                "No text was provided."
            ],
            "features": {},
            "explanation": (
                "No message content was provided for analysis."
            ),
            "recommendation": (
                "Provide email or message content for analysis."
            ),
        }

    # =========================================================================
    # MAXIMUM INPUT SIZE
    # =========================================================================

    if len(text) > MAX_TEXT_LENGTH:
        return {
            "text_type": text_type,
            "is_valid": False,
            "risk_score": 70.0,
            "severity": "HIGH",
            "prediction": "SUSPICIOUS",
            "confidence": 0.85,
            "indicators": [
                f"Text exceeds maximum supported length of "
                f"{MAX_TEXT_LENGTH} characters."
            ],
            "features": {
                "text_length": len(text),
            },
            "explanation": (
                "The message is too large to analyze safely in one pass."
            ),
            "recommendation": (
                "Analyze the message in smaller sections and "
                "investigate suspicious content separately."
            ),
        }

    # =========================================================================
    # FEATURE EXTRACTION
    # =========================================================================

    urgent_keywords = _find_keywords(
        text,
        URGENT_KEYWORDS,
    )

    credential_keywords = _find_keywords(
        text,
        CREDENTIAL_KEYWORDS,
    )

    financial_keywords = _find_keywords(
        text,
        FINANCIAL_KEYWORDS,
    )

    threat_keywords = _find_keywords(
        text,
        THREAT_KEYWORDS,
    )

    trust_keywords = _find_keywords(
        text,
        TRUST_KEYWORDS,
    )

    request_keywords = _find_keywords(
        text,
        REQUEST_KEYWORDS,
    )

    promotional_keywords = _find_keywords(
        text,
        PROMOTIONAL_KEYWORDS,
    )

    event_keywords = _find_keywords(
        text,
        EVENT_KEYWORDS,
    )

    registration_keywords = _find_keywords(
        text,
        REGISTRATION_KEYWORDS,
    )

    promotional_cta_keywords = _find_keywords(
        text,
        PROMOTIONAL_CTA_KEYWORDS,
    )

    urls = _extract_urls(text)

    email_addresses = _extract_emails(text)

    suspicious_attachments = _detect_suspicious_attachments(text)

    contains_otp_request = bool(
        OTP_PATTERN.search(text)
    )

    contains_money_reference = bool(
        MONEY_PATTERN.search(text)
    )

    excessive_caps = _detect_excessive_caps(text)

    excessive_exclamation = _detect_excessive_exclamation(text)

    obfuscated_text = _detect_obfuscation(text)

    html_or_script = _detect_html_or_script(text)

    word_count = len(
        re.findall(r"\b\w+\b", text)
    )

    # =========================================================================
    # PROMOTIONAL ANALYSIS
    # =========================================================================

    promotional = _detect_promotional_content(
        promotional_keywords=promotional_keywords,
        event_keywords=event_keywords,
        registration_keywords=registration_keywords,
        promotional_cta_keywords=promotional_cta_keywords,
        text=text,
    )

    spam_keywords = _find_keywords(
        text,
        SPAM_KEYWORDS,
    )

    spam = _detect_spam_content(
        spam_keywords=spam_keywords,
        urls=urls,
        suspicious_attachments=suspicious_attachments,
        excessive_caps=excessive_caps,
        excessive_exclamation=excessive_exclamation,
        text=text,
    )

    # =========================================================================
    # URL ANALYSIS
    # =========================================================================

    url_analysis = _analyze_urls(urls)

    suspicious_link = (
        url_analysis["suspicious_count"] > 0
        or url_analysis["unverified_count"] > 0
    )

    # =========================================================================
    # RISK SCORING
    # =========================================================================

    score = 0.0

    indicators: list[str] = []

    def add_risk(
        points: float,
        reason: str,
    ) -> None:
        nonlocal score

        score += points
        indicators.append(reason)

    # -------------------------------------------------------------------------
    # 1. Urgency
    # -------------------------------------------------------------------------

    if urgent_keywords:
        add_risk(
            min(20, len(urgent_keywords) * 4),
            "Urgency or pressure language detected: "
            + ", ".join(urgent_keywords[:8])
            + ".",
        )

    # -------------------------------------------------------------------------
    # 2. Credential requests
    # -------------------------------------------------------------------------

    if credential_keywords:
        add_risk(
            min(25, len(credential_keywords) * 5),
            "Credential/security-related terms detected: "
            + ", ".join(credential_keywords[:8])
            + ".",
        )

    # -------------------------------------------------------------------------
    # 3. Financial manipulation
    # -------------------------------------------------------------------------

    if financial_keywords:
        add_risk(
            min(20, len(financial_keywords) * 4),
            "Financial/payment-related terms detected: "
            + ", ".join(financial_keywords[:8])
            + ".",
        )

    # -------------------------------------------------------------------------
    # 4. Threat/fear tactics
    # -------------------------------------------------------------------------

    if threat_keywords:
        add_risk(
            min(20, len(threat_keywords) * 4),
            "Threat or fear-based language detected: "
            + ", ".join(threat_keywords[:8])
            + ".",
        )

    # -------------------------------------------------------------------------
    # 5. Action request
    # -------------------------------------------------------------------------

    if request_keywords:
        add_risk(
            min(15, len(request_keywords) * 3),
            "Action-request language detected: "
            + ", ".join(request_keywords[:8])
            + ".",
        )

    # -------------------------------------------------------------------------
    # 6. Links
    # -------------------------------------------------------------------------

    if urls:
        add_risk(
            10,
            f"Message contains {len(urls)} web link(s) "
            "that require destination analysis.",
        )

    # -------------------------------------------------------------------------
    # 7. OTP
    # -------------------------------------------------------------------------

    if contains_otp_request:
        add_risk(
            15,
            "Message appears to request or discuss "
            "an OTP/security verification code.",
        )

    # -------------------------------------------------------------------------
    # 8. Money reference
    # -------------------------------------------------------------------------

    if contains_money_reference:
        add_risk(
            8,
            "Message contains a monetary amount.",
        )

    # -------------------------------------------------------------------------
    # 9. Suspicious attachments
    # -------------------------------------------------------------------------

    if suspicious_attachments:
        add_risk(
            min(
                20,
                len(suspicious_attachments) * 8,
            ),
            "Potentially dangerous attachment type detected: "
            + ", ".join(suspicious_attachments)
            + ".",
        )

    # -------------------------------------------------------------------------
    # 10. Excessive uppercase
    # -------------------------------------------------------------------------

    if excessive_caps:
        add_risk(
            5,
            "Unusually high uppercase usage detected.",
        )

    # -------------------------------------------------------------------------
    # 11. Excessive exclamation
    # -------------------------------------------------------------------------

    if excessive_exclamation:
        add_risk(
            5,
            "Repeated exclamation marks indicate "
            "possible pressure or urgency.",
        )

    # -------------------------------------------------------------------------
    # 12. Obfuscation
    # -------------------------------------------------------------------------

    if obfuscated_text:
        add_risk(
            8,
            "Possible obfuscation of security-related "
            "words detected.",
        )

    # -------------------------------------------------------------------------
    # 13. HTML/script
    # -------------------------------------------------------------------------

    if html_or_script:
        add_risk(
            15,
            "HTML or script-like content detected.",
        )

    # -------------------------------------------------------------------------
    # 14. Suspicious URL characteristics
    # -------------------------------------------------------------------------

    if url_analysis["suspicious_count"] > 0:
        add_risk(
            min(
                25,
                url_analysis["suspicious_count"] * 10,
            ),
            "One or more links have suspicious characteristics.",
        )

    # -------------------------------------------------------------------------
    # 15. Promotional content
    #
    # Promotional content itself does NOT add phishing risk.
    # It is classified separately.
    # -------------------------------------------------------------------------

    if promotional["detected"]:
        indicators.append(
            "Promotional or marketing content detected: "
            + ", ".join(
                (
                    promotional_keywords
                    + event_keywords
                    + registration_keywords
                )[:10]
            )
            + "."
        )

    # =========================================================================
    # CORRELATION RULES
    # =========================================================================

    # Credential + link
    if credential_keywords and urls:
        add_risk(
            15,
            "Credential-related language is combined "
            "with a web link.",
        )

    # Urgency + credential
    if urgent_keywords and credential_keywords:
        add_risk(
            12,
            "Urgency is combined with a credential/security request.",
        )

    # Financial + urgency
    if financial_keywords and urgent_keywords:
        add_risk(
            12,
            "Financial content is combined with urgency or pressure.",
        )

    # Threat + request
    if threat_keywords and request_keywords:
        add_risk(
            10,
            "Threat/fear language is combined with "
            "a direct action request.",
        )

    # OTP + urgency
    if contains_otp_request and urgent_keywords:
        add_risk(
            12,
            "OTP/security-code request is combined with urgency.",
        )

    # Financial + credential + link
    if (
        financial_keywords
        and credential_keywords
        and urls
    ):
        add_risk(
            15,
            "Financial information, credentials and "
            "a web link appear together.",
        )

    # =========================================================================
    # PROMOTIONAL + SUSPICIOUS LINK
    # =========================================================================

    promotional_suspicious_link = (
        promotional["detected"]
        and suspicious_link
    )

    if promotional_suspicious_link:
        indicators.append(
            "Promotional content contains an "
            "unverified or suspicious link."
        )

        # Make this meaningful enough to become SUSPICIOUS,
        # but do not make it critical by itself.
        add_risk(
            15,
            "Promotional content is combined with "
            "an unverified or suspicious link.",
        )

    # =========================================================================
    # FINAL SCORE
    # =========================================================================

    score = _clamp_score(score)

    severity = _get_severity(score)

    # =========================================================================
    # PREDICTION
    # =========================================================================

    # Strong phishing signals always have priority.
    if score >= 80:
        prediction = "PHISHING"

    elif score >= 60:
        prediction = "LIKELY_PHISHING"

    # Promotional + suspicious/unverified link gets SUSPICIOUS.
    elif promotional_suspicious_link:
        prediction = "SUSPICIOUS"

    elif score >= 40:
        prediction = "SUSPICIOUS"

    elif spam["detected"]:
        prediction = "SPAM"

    elif promotional["detected"]:
        prediction = "PROMOTIONAL"

    elif score >= 20:
        prediction = "LOW_RISK"

    else:
        prediction = "SAFE"

    # =========================================================================
    # CONFIDENCE
    # =========================================================================

    # Rule-engine confidence.
    # This is NOT the probability that the message is malicious.

    if score >= 80:
        confidence = 0.90

    elif score >= 60:
        confidence = 0.80

    elif score >= 40:
        confidence = 0.70

    elif promotional_suspicious_link:
        confidence = 0.70

    elif spam["detected"]:
        confidence = 0.72

    elif promotional["detected"]:
        confidence = 0.75

    elif score >= 20:
        confidence = 0.60

    else:
        confidence = 0.55

    # =========================================================================
    # SIMPLE EXPLANATION
    # =========================================================================

    explanation = _build_simple_explanation(
        prediction=prediction,
        promotional=promotional,
        url_analysis=url_analysis,
        urgent_keywords=urgent_keywords,
        credential_keywords=credential_keywords,
        financial_keywords=financial_keywords,
        threat_keywords=threat_keywords,
        request_keywords=request_keywords,
        contains_otp_request=contains_otp_request,
        suspicious_attachments=suspicious_attachments,
        spam=spam,
    )

    # =========================================================================
    # RECOMMENDATION
    # =========================================================================

    if prediction in {
        "PHISHING",
        "LIKELY_PHISHING",
    }:
        recommendation = (
            "Do not click links or open attachments. "
            "Do not share passwords, OTPs or financial information. "
            "Report the message if necessary."
        )

    elif prediction == "SUSPICIOUS":
        recommendation = (
            "Verify the sender and link before taking action. "
            "Avoid entering passwords or personal information."
        )

    elif prediction == "SPAM":
        recommendation = (
            "This message contains common spam signals. "
            "Avoid clicking links, downloading attachments, or sharing personal information."
        )

    elif prediction == "PROMOTIONAL":
        recommendation = (
            "This appears to be promotional content. "
            "You can review it, but verify unexpected links before opening them."
        )

    elif severity == "LOW":
        recommendation = (
            "No strong phishing pattern was detected, but verify "
            "unexpected requests before taking action."
        )

    else:
        recommendation = (
            "No major phishing indicators were detected. "
            "Continue to be careful with unexpected links and requests."
        )

    # =========================================================================
    # FINAL RESPONSE
    # =========================================================================

    return {
        "text_type": text_type,
        "is_valid": True,
        "risk_score": score,
        "severity": severity,
        "prediction": prediction,
        "confidence": confidence,
        "indicators": indicators,

        "features": {
            # Basic content information
            "text_length": len(text),
            "word_count": word_count,

            # Existing security signals
            "urgent_keywords": urgent_keywords,
            "credential_keywords": credential_keywords,
            "financial_keywords": financial_keywords,
            "threat_keywords": threat_keywords,
            "trust_keywords": trust_keywords,
            "request_keywords": request_keywords,

            # URLs
            "url_count": len(urls),
            "urls": urls,
            "url_analysis": url_analysis,
            "suspicious_link": suspicious_link,

            # Email information
            "email_addresses": email_addresses,

            # Attachments
            "suspicious_attachments": suspicious_attachments,

            # Security indicators
            "otp_reference": contains_otp_request,
            "money_reference": contains_money_reference,
            "excessive_caps": excessive_caps,
            "excessive_exclamation": excessive_exclamation,
            "obfuscated_text": obfuscated_text,
            "html_or_script": html_or_script,

            # Promotional tracking
            "promotional_detected": promotional["detected"],
            "promotional_category": promotional["category"],
            "promotional_keywords": promotional[
                "promotional_keywords"
            ],
            "event_keywords": promotional[
                "event_keywords"
            ],
            "registration_keywords": promotional[
                "registration_keywords"
            ],
            "promotional_cta_keywords": promotional[
                "promotional_cta_keywords"
            ],
            "unsubscribe_detected": promotional[
                "unsubscribe_detected"
            ],
            "promotional_suspicious_link": (
                promotional_suspicious_link
            ),

            # Spam tracking
            "spam_detected": spam["detected"],
            "spam_score": spam["score"],
            "spam_keywords": spam["keywords"],
            "spam_reasons": spam["reasons"],
        },

        "content_category": (
            "PHISHING"
            if prediction in {"PHISHING", "LIKELY_PHISHING"}
            else "SUSPICIOUS"
            if prediction == "SUSPICIOUS"
            else "SPAM"
            if prediction == "SPAM"
            else "PROMOTIONAL"
            if prediction == "PROMOTIONAL"
            else "LEGITIMATE"
        ),

        # Simple user-friendly explanation
        "explanation": explanation,

        "recommendation": recommendation,
    }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def analyze_email(text: str) -> dict[str, Any]:
    """Analyze email content."""

    return analyze_text(
        text,
        text_type="email",
    )


def analyze_message(text: str) -> dict[str, Any]:
    """Analyze SMS/chat/social-media message content."""

    return analyze_text(
        text,
        text_type="message",
    )


def predict(text: str) -> dict[str, Any]:
    """Compatibility API for future ML model integration."""

    return analyze_text(text)