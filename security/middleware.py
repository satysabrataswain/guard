from __future__ import annotations

from django.http import JsonResponse


class APISecurityMiddleware:
    """
    Defense-in-depth protection for the JSON API.

    Django/DRF ORM queries remain parameterized; this middleware does not
    try to block SQL keywords because blacklist-based SQL filtering is
    bypassable and can reject legitimate text. Instead it limits request
    metadata size and adds security headers to API responses.
    """

    MAX_QUERY_STRING_LENGTH = 8 * 1024
    MAX_PARAMETER_LENGTH = 4 * 1024

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith("/api/"):
            if len(request.META.get("QUERY_STRING", "")) > self.MAX_QUERY_STRING_LENGTH:
                return JsonResponse(
                    {"detail": "Query string is too large."},
                    status=414,
                )

            for key, values in request.GET.lists():
                if len(str(key)) > self.MAX_PARAMETER_LENGTH:
                    return JsonResponse(
                        {"detail": "Query parameter name is too long."},
                        status=400,
                    )

                for value in values:
                    if len(str(value)) > self.MAX_PARAMETER_LENGTH:
                        return JsonResponse(
                            {"detail": "Query parameter value is too long."},
                            status=400,
                        )

            if request.method == "TRACE":
                return JsonResponse(
                    {"detail": "HTTP TRACE is not allowed."},
                    status=405,
                )

        response = self.get_response(request)

        if request.path.startswith("/api/"):
            response["X-Content-Type-Options"] = "nosniff"
            response["X-Frame-Options"] = "DENY"
            response["Referrer-Policy"] = "same-origin"
            response["Permissions-Policy"] = (
                "camera=(), microphone=(), geolocation=(), "
                "usb=(), payment=()"
            )
            response["Cache-Control"] = "no-store"
            response["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
            )

        return response
