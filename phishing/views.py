import ipaddress
from urllib.parse import urlparse

from django.core.validators import validate_email
from django.core.exceptions import ValidationError

from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import (
    PhishingScan,
    URLAnalysis,
    EmailAnalysis,
)

from .serializers import (
    PhishingScanSerializer,
)

from audit_logs.models import AuditLog
from accounts.utils import get_client_ip


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "account",
    "password",
    "secure",
    "security",
    "update",
    "confirm",
    "urgent",
    "wallet",
    "bank",
    "payment",
    "signin",
]

URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
]

URGENT_KEYWORDS = [
    "urgent",
    "immediately",
    "action required",
    "account suspended",
    "account blocked",
    "verify now",
    "last warning",
]

ATTACHMENT_KEYWORDS = [
    "attachment",
    ".exe",
    ".zip",
    ".rar",
    ".scr",
    ".js",
    ".bat",
    ".docm",
]


def get_severity(score):

    if score <= 19:
        return "SAFE"

    if score <= 39:
        return "LOW"

    if score <= 59:
        return "MEDIUM"

    if score <= 79:
        return "HIGH"

    return "CRITICAL"


def detect_ip_address(hostname):

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


class PhishingScanListView(
    generics.ListAPIView
):

    serializer_class = PhishingScanSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):

        return PhishingScan.objects.filter(
            user=self.request.user
        ).order_by("-created_at")


class PhishingScanDetailView(
    generics.RetrieveAPIView
):

    serializer_class = PhishingScanSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):

        return PhishingScan.objects.filter(
            user=self.request.user
        )


class URLAnalyzeView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        url = request.data.get("url")

        if not url:

            return Response(
                {
                    "detail":
                    "url is required."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        parsed = urlparse(url)

        if parsed.scheme not in [
            "http",
            "https",
        ] or not parsed.netloc:

            return Response(
                {
                    "detail":
                    "Invalid URL."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        hostname = parsed.hostname or ""

        lower_url = url.lower()

        score = 0
        evidence = []

        uses_https = (
            parsed.scheme == "https"
        )

        if not uses_https:

            score += 15

            evidence.append(
                "URL does not use HTTPS."
            )

        url_length = len(url)

        if url_length > 100:

            score += 15

            evidence.append(
                "URL is unusually long."
            )

        elif url_length > 75:

            score += 8

            evidence.append(
                "URL is longer than normal."
            )

        has_ip = detect_ip_address(
            hostname
        )

        if has_ip:

            score += 25

            evidence.append(
                "URL uses an IP address instead of a domain."
            )

        has_keyword = any(
            keyword in lower_url
            for keyword in SUSPICIOUS_KEYWORDS
        )

        if has_keyword:

            score += 15

            evidence.append(
                "URL contains security-related keywords."
            )

        has_shortener = any(
            hostname.lower().endswith(
                shortener
            )
            for shortener in URL_SHORTENERS
        )

        if has_shortener:

            score += 10

            evidence.append(
                "URL uses a URL shortening service."
            )

        if "@" in url:

            score += 20

            evidence.append(
                "URL contains an @ character."
            )

        if url.count(".") > 4:

            score += 10

            evidence.append(
                "URL contains an unusually high number of subdomains."
            )

        score = min(score, 100)

        result = get_severity(score)

        if not evidence:

            explanation = (
                "No obvious phishing indicators "
                "were detected by the initial URL analysis."
            )

        else:

            explanation = " ".join(evidence)

        scan = PhishingScan.objects.create(
            user=request.user,
            scan_type="URL",
            input_data=url,
            risk_score=score,
            result=result,
            explanation=explanation,
            status="COMPLETED",
        )

        URLAnalysis.objects.create(
            scan=scan,
            domain=hostname,
            uses_https=uses_https,
            url_length=url_length,
            has_ip_address=has_ip,
            has_suspicious_keyword=has_keyword,
            has_shortener=has_shortener,
            redirect_count=0,
            analysis_details={
                "evidence": evidence,
                "note": (
                    "Initial analysis only. "
                    "Domain reputation, redirect "
                    "chain and AI model analysis "
                    "will be added later."
                ),
            },
        )

        AuditLog.objects.create(
            user=request.user,
            action="PHISHING_SCAN",
            ip_address=get_client_ip(request),
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"URL phishing scan performed. "
                f"Scan ID: {scan.id}"
            ),
            status="SUCCESS",
        )

        return Response(
            {
                "message":
                "URL analysis completed.",

                "scan":
                PhishingScanSerializer(
                    scan
                ).data,
            },
            status=status.HTTP_201_CREATED,
        )


class EmailAnalyzeView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        sender = request.data.get(
            "sender",
            "",
        )

        subject = request.data.get(
            "subject",
            "",
        )

        body = request.data.get(
            "body",
            "",
        )

        if not subject and not body:

            return Response(
                {
                    "detail":
                    "subject or body is required."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if sender:

            try:

                validate_email(sender)

            except ValidationError:

                return Response(
                    {
                        "detail":
                        "Invalid sender email."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        full_text = (
            f"{subject} {body}"
        ).lower()

        score = 0
        evidence = []

        has_suspicious_keyword = any(
            keyword in full_text
            for keyword in SUSPICIOUS_KEYWORDS
        )

        if has_suspicious_keyword:

            score += 15

            evidence.append(
                "Security or account-related keywords detected."
            )

        has_urgent_language = any(
            keyword in full_text
            for keyword in URGENT_KEYWORDS
        )

        if has_urgent_language:

            score += 25

            evidence.append(
                "Urgent or threatening language detected."
            )

        has_suspicious_link = (
            "http://" in full_text
            or "https://" in full_text
            or "bit.ly/" in full_text
            or "tinyurl.com/" in full_text
        )

        if has_suspicious_link:

            score += 20

            evidence.append(
                "Link detected in the message."
            )

        has_attachment_warning = any(
            keyword in full_text
            for keyword in ATTACHMENT_KEYWORDS
        )

        if has_attachment_warning:

            score += 20

            evidence.append(
                "Potentially risky attachment or file type detected."
            )

        if sender:

            sender_domain = sender.split("@")[-1].lower()

            if any(
                brand in sender_domain
                for brand in [
                    "paypal",
                    "microsoft",
                    "google",
                    "amazon",
                    "apple",
                ]
            ):

                pass

        score = min(score, 100)

        result = get_severity(score)

        if not evidence:

            explanation = (
                "No obvious phishing indicators "
                "were detected by the initial email analysis."
            )

        else:

            explanation = " ".join(evidence)

        scan = PhishingScan.objects.create(
            user=request.user,
            scan_type="EMAIL",
            input_data=body,
            risk_score=score,
            result=result,
            explanation=explanation,
            status="COMPLETED",
        )

        EmailAnalysis.objects.create(
            scan=scan,
            sender=sender,
            subject=subject,
            has_suspicious_keyword=(
                has_suspicious_keyword
            ),
            has_urgent_language=(
                has_urgent_language
            ),
            has_suspicious_link=(
                has_suspicious_link
            ),
            has_attachment_warning=(
                has_attachment_warning
            ),
            analysis_details={
                "evidence": evidence,
                "note": (
                    "Initial NLP/rule-based analysis. "
                    "AI NLP model will be connected later."
                ),
            },
        )

        AuditLog.objects.create(
            user=request.user,
            action="PHISHING_SCAN",
            ip_address=get_client_ip(request),
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"Email phishing scan performed. "
                f"Scan ID: {scan.id}"
            ),
            status="SUCCESS",
        )

        return Response(
            {
                "message":
                "Email analysis completed.",

                "scan":
                PhishingScanSerializer(
                    scan
                ).data,
            },
            status=status.HTTP_201_CREATED,
        )


class PhishingScanDeleteView(
    generics.DestroyAPIView
):

    serializer_class = PhishingScanSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):

        return PhishingScan.objects.filter(
            user=self.request.user
        )