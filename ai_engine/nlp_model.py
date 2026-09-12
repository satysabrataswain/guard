"""
NLP-based Phishing and Social Engineering Detection Engine.

Analyzes:
- Emails
- SMS/messages
- Social-media messages
- Other text content

This is an explainable rule-based NLP foundation.
A trained ML/Transformer model can be integrated later.
"""

from __future__ import annotations

import re
from typing import Any


# ============================================================================
# CONFIGURATION
# ============================================================================

MAX_TEXT_LENGTH = 50_000


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

    return URL_PATTERN.findall(text)


def _extract_emails(text: str) -> list[str]:
    """Extract email addresses."""

    return EMAIL_PATTERN.findall(text)


def _detect_suspicious_attachments(text: str) -> list[str]:
    """
    Detect potentially dangerous attachment filenames.

    Important:
    Normal domains such as:
        example.com
        google.com
        microsoft.com

    must NOT be classified as .com attachments.

    The extension must appear as part of a filename-like token.
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
    """
    Detect unusually high uppercase usage.

    This is only a supporting signal because legitimate alerts
    can also contain uppercase text.
    """

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
# MAIN NLP ANALYSIS
# ============================================================================

def analyze_text(
    text: str,
    text_type: str = "message",
) -> dict[str, Any]:
    """
    Analyze email/message text for phishing and social-engineering indicators.

    Returns a JSON-serializable dictionary containing:
        risk_score
        severity
        prediction
        confidence
        indicators
        features
        recommendation

    No external network request is performed.
    """

    if text is None:
        text = ""

    text = str(text)

    # ------------------------------------------------------------------------
    # Empty input
    # ------------------------------------------------------------------------

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
            "recommendation": (
                "Provide email or message content for analysis."
            ),
        }

    # ------------------------------------------------------------------------
    # Maximum input size
    # ------------------------------------------------------------------------

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

    # ------------------------------------------------------------------------
    # 1. Urgency
    # ------------------------------------------------------------------------

    if urgent_keywords:
        add_risk(
            min(20, len(urgent_keywords) * 4),
            "Urgency or pressure language detected: "
            + ", ".join(urgent_keywords[:8])
            + ".",
        )

    # ------------------------------------------------------------------------
    # 2. Credential requests
    # ------------------------------------------------------------------------

    if credential_keywords:
        add_risk(
            min(25, len(credential_keywords) * 5),
            "Credential/security-related terms detected: "
            + ", ".join(credential_keywords[:8])
            + ".",
        )

    # ------------------------------------------------------------------------
    # 3. Financial manipulation
    # ------------------------------------------------------------------------

    if financial_keywords:
        add_risk(
            min(20, len(financial_keywords) * 4),
            "Financial/payment-related terms detected: "
            + ", ".join(financial_keywords[:8])
            + ".",
        )

    # ------------------------------------------------------------------------
    # 4. Threat/fear tactics
    # ------------------------------------------------------------------------

    if threat_keywords:
        add_risk(
            min(20, len(threat_keywords) * 4),
            "Threat or fear-based language detected: "
            + ", ".join(threat_keywords[:8])
            + ".",
        )

    # ------------------------------------------------------------------------
    # 5. Action request
    # ------------------------------------------------------------------------

    if request_keywords:
        add_risk(
            min(15, len(request_keywords) * 3),
            "Action-request language detected: "
            + ", ".join(request_keywords[:8])
            + ".",
        )

    # ------------------------------------------------------------------------
    # 6. Links
    # ------------------------------------------------------------------------

    if urls:
        add_risk(
            10,
            f"Message contains {len(urls)} web link(s) "
            "that require destination analysis.",
        )

    # ------------------------------------------------------------------------
    # 7. OTP
    # ------------------------------------------------------------------------

    if contains_otp_request:
        add_risk(
            15,
            "Message appears to request or discuss "
            "an OTP/security verification code.",
        )

    # ------------------------------------------------------------------------
    # 8. Money reference
    # ------------------------------------------------------------------------

    if contains_money_reference:
        add_risk(
            8,
            "Message contains a monetary amount.",
        )

    # ------------------------------------------------------------------------
    # 9. Suspicious attachments
    # ------------------------------------------------------------------------

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

    # ------------------------------------------------------------------------
    # 10. Excessive uppercase
    # ------------------------------------------------------------------------

    if excessive_caps:
        add_risk(
            5,
            "Unusually high uppercase usage detected.",
        )

    # ------------------------------------------------------------------------
    # 11. Excessive exclamation
    # ------------------------------------------------------------------------

    if excessive_exclamation:
        add_risk(
            5,
            "Repeated exclamation marks indicate "
            "possible pressure or urgency.",
        )

    # ------------------------------------------------------------------------
    # 12. Obfuscation
    # ------------------------------------------------------------------------

    if obfuscated_text:
        add_risk(
            8,
            "Possible obfuscation of security-related "
            "words detected.",
        )

    # ------------------------------------------------------------------------
    # 13. HTML/script
    # ------------------------------------------------------------------------

    if html_or_script:
        add_risk(
            15,
            "HTML or script-like content detected.",
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
    # FINAL SCORE
    # =========================================================================

    score = _clamp_score(score)

    severity = _get_severity(score)

    # =========================================================================
    # PREDICTION
    # =========================================================================

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

    # Rule-engine confidence.
    # This is NOT the probability that the message is malicious.

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

    # =========================================================================
    # RECOMMENDATION
    # =========================================================================

    if severity == "CRITICAL":
        recommendation = (
            "Quarantine the message, avoid links/attachments, "
            "and investigate the sender and destinations."
        )

    elif severity == "HIGH":
        recommendation = (
            "Do not click links or open attachments. "
            "Quarantine or report the message for investigation."
        )

    elif severity == "MEDIUM":
        recommendation = (
            "Treat the message with caution and independently "
            "verify the sender and requested action."
        )

    elif severity == "LOW":
        recommendation = (
            "No strong phishing pattern was detected, but verify "
            "unexpected requests before taking action."
        )

    else:
        recommendation = (
            "No major phishing or social-engineering indicators "
            "were detected by the current NLP rules."
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
            "text_length": len(text),
            "word_count": word_count,
            "urgent_keywords": urgent_keywords,
            "credential_keywords": credential_keywords,
            "financial_keywords": financial_keywords,
            "threat_keywords": threat_keywords,
            "trust_keywords": trust_keywords,
            "request_keywords": request_keywords,
            "url_count": len(urls),
            "urls": urls,
            "email_addresses": email_addresses,
            "suspicious_attachments": suspicious_attachments,
            "otp_reference": contains_otp_request,
            "money_reference": contains_money_reference,
            "excessive_caps": excessive_caps,
            "excessive_exclamation": excessive_exclamation,
            "obfuscated_text": obfuscated_text,
            "html_or_script": html_or_script,
        },
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