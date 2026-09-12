from rest_framework import serializers

from .models import (
    PhishingScan,
    URLAnalysis,
    EmailAnalysis,
)


class URLAnalysisSerializer(serializers.ModelSerializer):

    class Meta:
        model = URLAnalysis

        fields = [
            "id",
            "domain",
            "uses_https",
            "url_length",
            "has_ip_address",
            "has_suspicious_keyword",
            "has_shortener",
            "redirect_count",
            "analysis_details",
            "created_at",
        ]

        read_only_fields = [
            "id",
            "created_at",
        ]


class EmailAnalysisSerializer(serializers.ModelSerializer):

    class Meta:
        model = EmailAnalysis

        fields = [
            "id",
            "sender",
            "subject",
            "has_suspicious_keyword",
            "has_urgent_language",
            "has_suspicious_link",
            "has_attachment_warning",
            "analysis_details",
            "created_at",
        ]

        read_only_fields = [
            "id",
            "created_at",
        ]


class PhishingScanSerializer(serializers.ModelSerializer):

    url_analysis = URLAnalysisSerializer(
        read_only=True
    )

    email_analysis = EmailAnalysisSerializer(
        read_only=True
    )

    class Meta:
        model = PhishingScan

        fields = [
            "id",
            "user",
            "scan_type",
            "input_data",
            "risk_score",
            "result",
            "explanation",
            "status",
            "created_at",
            "updated_at",
            "url_analysis",
            "email_analysis",
        ]

        read_only_fields = [
            "id",
            "user",
            "risk_score",
            "result",
            "explanation",
            "status",
            "created_at",
            "updated_at",
            "url_analysis",
            "email_analysis",
        ]