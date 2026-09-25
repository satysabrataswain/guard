import json
import os
import tempfile
import ipaddress
import socket

import requests
from typing import Any

from django.db import transaction
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser

from accounts.utils import get_client_ip
from audit_logs.models import AuditLog

from ai_engine.anomaly_model import (
    analyze_behavior,
    analyze_login,
)
from ai_engine.correlation_engine import (
    correlate_threat_signals,
)
from ai_engine.malware_model import analyze_malware_file
from ai_engine.trained_classifiers import analyze_phishing_email_ml, analyze_phishing_url_ml
from ai_engine.nlp_model import (
    analyze_email,
    analyze_message,
)
from ai_engine.phishing_model import analyze_url
from ai_engine.risk_engine import analyze_risk

from incidents.models import (
    Incident,
    IncidentEvidence,
    ResponseAction,
)

from .models import (
    Threat,
    ThreatAnalysis,
    ThreatEvidence,
)
from .serializers import ThreatSerializer


# Maximum accepted malware/Android APK upload size: 200 MiB.
MAX_MALWARE_UPLOAD_SIZE = 200 * 1024 * 1024


# ============================================================================
# GENERAL HELPERS
# ============================================================================


def _stringify_input(value: Any) -> str:
    """
    Convert API input into a safe string for Threat.input_data.
    """

    if isinstance(value, str):
        return value

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            default=str,
        )
    except (TypeError, ValueError):
        return str(value)


def _as_dict(value: Any) -> dict:
    """
    Convert input into a dictionary when possible.
    """

    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        try:
            parsed = json.loads(value)

            if isinstance(parsed, dict):
                return parsed

        except (
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            pass

    return {}


def _safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    """
    Normalize any score to 0-100.
    """

    try:
        number = float(value)

    except (TypeError, ValueError):
        return default

    return round(
        max(
            0.0,
            min(
                100.0,
                number,
            ),
        ),
        2,
    )


def _normalize_confidence(
    value: Any,
) -> float:
    """
    Normalize confidence.

    Supported:
        0.0 - 1.0  -> converted to percentage
        0 - 100    -> kept as percentage
    """

    try:
        confidence = float(value)

    except (TypeError, ValueError):
        return 0.0

    if 0.0 <= confidence <= 1.0:
        confidence *= 100.0

    return round(
        max(
            0.0,
            min(
                100.0,
                confidence,
            ),
        ),
        2,
    )


def _unique_indicators(
    model_results: list[tuple[str, dict]],
) -> list[str]:
    """
    Collect unique indicators from all detection engines.
    """

    indicators = []

    for _, result in model_results:

        if not isinstance(
            result,
            dict,
        ):
            continue

        values = result.get(
            "indicators",
            [],
        )

        if not isinstance(
            values,
            list,
        ):
            continue

        for indicator in values:

            if indicator is None:
                continue

            text = str(
                indicator
            ).strip()

            if not text:
                continue

            if text not in indicators:
                indicators.append(text)

    return indicators


# ============================================================================
# CORRELATION HELPERS
# ============================================================================


def _build_correlation_signals(
    model_results: list[tuple[str, dict]],
    request_data: Any = None,
) -> list[dict]:
    """
    Convert detection-engine results and optional API-provided
    signals into the unified correlation-engine format.

    The original single-source detection flow remains unchanged.
    Correlation is additive and is only applied when multiple
    distinct sources are available.
    """

    signals = []

    engine_source_map = {
        "URL_PHISHING_ENGINE": "URL",
        "EMAIL_NLP_ENGINE": "EMAIL",
        "MESSAGE_NLP_ENGINE": "MESSAGE",
        "LOGIN_ANOMALY_ENGINE": "LOGIN",
        "BEHAVIOUR_ANOMALY_ENGINE": "DEVICE",
        "NETWORK_ENGINE": "NETWORK",
        "IMAGE_ENGINE": "IMAGE",
        "VIDEO_ENGINE": "VIDEO",
        "DEEPFAKE_ENGINE": "VIDEO",
        "IDENTITY_ENGINE": "IDENTITY",
        "MALWARE_ENGINE": "FILE",
    }

    # ------------------------------------------------------------------
    # Detection engine results
    # ------------------------------------------------------------------

    for model_name, result in model_results:

        if not isinstance(
            result,
            dict,
        ):
            continue

        score = _safe_float(
            result.get(
                "risk_score",
                result.get(
                    "score",
                    0,
                ),
            )
        )

        source = engine_source_map.get(
            model_name,
            model_name.replace(
                "_ENGINE",
                "",
            ),
        )

        indicators = result.get(
            "indicators",
            [],
        )

        if not isinstance(
            indicators,
            list,
        ):
            indicators = []

        signals.append(
            {
                "source": source,
                "score": score,
                "indicators": [
                    str(item)
                    for item in indicators
                    if item is not None
                    and str(item).strip()
                ],
            }
        )

    # ------------------------------------------------------------------
    # Optional externally supplied correlation signals
    #
    # Accepted formats:
    #
    # {
    #     "correlation_signals": [...]
    # }
    #
    # OR directly:
    #
    # [...]
    # ------------------------------------------------------------------

    if isinstance(
        request_data,
        list,
    ):
        external_signals = request_data

    elif isinstance(
        request_data,
        dict,
    ):
        external_signals = request_data.get(
            "correlation_signals",
            [],
        )

    else:
        external_signals = []

    if not isinstance(
        external_signals,
        list,
    ):
        external_signals = []

    for signal in external_signals:

        if not isinstance(
            signal,
            dict,
        ):
            continue

        source = signal.get(
            "source"
        )

        if not source:
            continue

        score = _safe_float(
            signal.get(
                "score",
                signal.get(
                    "risk_score",
                    0,
                ),
            )
        )

        indicators = signal.get(
            "indicators",
            [],
        )

        if not isinstance(
            indicators,
            list,
        ):
            indicators = []

        signals.append(
            {
                "source": str(
                    source
                ).upper(),
                "score": score,
                "indicators": [
                    str(item)
                    for item in indicators
                    if item is not None
                    and str(item).strip()
                ],
            }
        )

    return signals


def _get_distinct_correlation_sources(
    signals: list[dict],
) -> set[str]:
    """
    Return unique normalized source names.
    """

    sources = set()

    for signal in signals:

        if not isinstance(
            signal,
            dict,
        ):
            continue

        source = signal.get(
            "source"
        )

        if not source:
            continue

        sources.add(
            str(source).upper().strip()
        )

    return sources


# ============================================================================
# MODEL RESULT PERSISTENCE
# ============================================================================


def _save_model_result(
    threat: Threat,
    model_name: str,
    result: dict,
) -> None:
    """
    Save one detection-engine result into ThreatAnalysis
    and its indicators into ThreatEvidence.
    """

    if not isinstance(
        result,
        dict,
    ):
        result = {}

    score = _safe_float(
        result.get(
            "risk_score",
            result.get(
                "score",
                0,
            ),
        )
    )

    confidence = _normalize_confidence(
        result.get(
            "confidence",
            0,
        )
    )

    prediction = str(
        result.get(
            "prediction",
            "UNKNOWN",
        )
    )[:100]

    ThreatAnalysis.objects.create(
        threat=threat,
        model_name=model_name,
        model_version="1.0-rule-engine",
        prediction=prediction,
        confidence=confidence,
        score=score,
        analysis_result=result,
    )

    indicators = result.get(
        "indicators",
        [],
    )

    if not isinstance(
        indicators,
        list,
    ):
        return

    evidence_objects = []

    for indicator in indicators:

        if indicator is None:
            continue

        indicator_text = str(
            indicator
        ).strip()

        if not indicator_text:
            continue

        evidence_objects.append(
            ThreatEvidence(
                threat=threat,
                evidence_type=model_name,
                evidence_value=indicator_text,
                risk_contribution=score,
            )
        )

    if evidence_objects:

        ThreatEvidence.objects.bulk_create(
            evidence_objects
        )


# ============================================================================
# DETECTION ENGINE ROUTER
# ============================================================================


def _run_detection_engines(
    threat_type: str,
    source_type: str,
    input_data: Any,
) -> list[tuple[str, dict]]:
    """
    Route incoming data to the existing Guard detection engines.

    Returns:

        [
            ("ENGINE_NAME", result_dict),
            ...
        ]
    """

    results = []

    text_input = _stringify_input(
        input_data
    )

    # ----------------------------------------------------------------------
    # URL
    # ----------------------------------------------------------------------

    if source_type == "URL":

        result = analyze_url(
            text_input
        )

        results.append(
            (
                "URL_PHISHING_ENGINE",
                result,
            )
        )

        ml_result = analyze_phishing_url_ml(text_input)
        if ml_result is not None:
            results.append(("PHISHING_URL_ML_ENGINE", ml_result))

        return results

    # ----------------------------------------------------------------------
    # EMAIL
    # ----------------------------------------------------------------------

    if source_type == "EMAIL":

        result = analyze_email(
            text_input
        )

        results.append(
            (
                "EMAIL_NLP_ENGINE",
                result,
            )
        )

        ml_result = analyze_phishing_email_ml(text_input)
        if ml_result is not None:
            results.append(("PHISHING_EMAIL_ML_ENGINE", ml_result))

        return results

    # ----------------------------------------------------------------------
    # MESSAGE
    # ----------------------------------------------------------------------

    if source_type == "MESSAGE":

        result = analyze_message(
            text_input
        )

        results.append(
            (
                "MESSAGE_NLP_ENGINE",
                result,
            )
        )

        return results

    # ----------------------------------------------------------------------
    # LOGIN
    # ----------------------------------------------------------------------

    if source_type == "LOGIN":

        data = _as_dict(
            input_data
        )

        result = analyze_login(
            failed_attempts=data.get(
                "failed_attempts",
                0,
            ),
            new_ip=data.get(
                "new_ip",
                False,
            ),
            new_device=data.get(
                "new_device",
                False,
            ),
            new_location=data.get(
                "new_location",
                False,
            ),
            unusual_time=data.get(
                "unusual_time",
                False,
            ),
            impossible_travel=data.get(
                "impossible_travel",
                False,
            ),
            suspicious_network=data.get(
                "suspicious_network",
                False,
            ),
        )

        results.append(
            (
                "LOGIN_ANOMALY_ENGINE",
                result,
            )
        )

        return results

    # ----------------------------------------------------------------------
    # DEVICE / BEHAVIOUR
    # ----------------------------------------------------------------------

    if source_type == "DEVICE":

        data = _as_dict(
            input_data
        )

        result = analyze_behavior(
            unusual_access=data.get(
                "unusual_access",
                False,
            ),
            unusual_resource_access=data.get(
                "unusual_resource_access",
                False,
            ),
            unusual_request_volume=data.get(
                "unusual_request_volume",
                False,
            ),
            new_device=data.get(
                "new_device",
                False,
            ),
            new_location=data.get(
                "new_location",
                False,
            ),
            suspicious_network=data.get(
                "suspicious_network",
                False,
            ),
        )

        results.append(
            (
                "BEHAVIOUR_ANOMALY_ENGINE",
                result,
            )
        )

        return results

    # ----------------------------------------------------------------------
    # Threat types where NLP can provide useful text analysis
    # ----------------------------------------------------------------------

    if threat_type == "PHISHING":

        result = analyze_message(
            text_input
        )

        results.append(
            (
                "NLP_ENGINE",
                result,
            )
        )

        return results

    if threat_type == "SUSPICIOUS_EMAIL":

        result = analyze_email(
            text_input
        )

        results.append(
            (
                "NLP_ENGINE",
                result,
            )
        )

        return results

    if threat_type == "SUSPICIOUS_MESSAGE":

        result = analyze_message(
            text_input
        )

        results.append(
            (
                "NLP_ENGINE",
                result,
            )
        )

        return results

    # ----------------------------------------------------------------------
    # No dedicated engine yet
    # ----------------------------------------------------------------------

    return results


# ============================================================================
# MALWARE FILE ANALYSIS API
# ============================================================================

def _lookup_public_ip(ip_value: str) -> dict:
    """Return normalized public IP intelligence without exposing provider-specific UI."""

    ip_obj = ipaddress.ip_address(ip_value)

    if ip_obj.version != 4:
        raise ValueError("Self Protection currently accepts IPv4 for lookup.")

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    ):
        raise ValueError(
            "Enter a public IPv4 address. Private/local IPv4 addresses cannot be geolocated publicly."
        )

    response = requests.get(
        f"https://ipwho.is/{ip_obj}",
        timeout=8,
        headers={
            "User-Agent": "CyberGuard-SelfProtection/1.0",
        },
    )
    response.raise_for_status()

    data = response.json()

    if not data.get("success", False):
        raise ValueError(
            str(data.get("message", "IP lookup failed."))
        )

    connection = data.get("connection") or {}
    timezone = data.get("timezone") or {}
    flag = data.get("flag") or {}

    reverse_dns = None

    try:
        reverse_dns = socket.gethostbyaddr(
            str(ip_obj)
        )[0]
    except (socket.herror, socket.gaierror, OSError):
        reverse_dns = None

    return {
        "ip": data.get("ip", str(ip_obj)),
        "version": data.get("type", "IPv4"),
        "is_public": True,
        "continent": data.get("continent"),
        "continent_code": data.get("continent_code"),
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "region_code": data.get("region_code"),
        "city": data.get("city"),
        "postal": data.get("postal"),
        "capital": data.get("capital"),
        "calling_code": data.get("calling_code"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "is_eu": data.get("is_eu"),
        "borders": data.get("borders"),
        "flag": flag,
        "connection": {
            "asn": connection.get("asn"),
            "organization": connection.get("org"),
            "isp": connection.get("isp"),
            "domain": connection.get("domain"),
        },
        "timezone": {
            "id": timezone.get("id"),
            "abbr": timezone.get("abbr"),
            "is_dst": timezone.get("is_dst"),
            "offset": timezone.get("offset"),
            "utc": timezone.get("utc"),
            "current_time": timezone.get("current_time"),
        },
        "public_exposure": {
            "reverse_dns": reverse_dns,
            "network_domain": connection.get("domain"),
            "asn": connection.get("asn"),
            "organization": connection.get("org"),
            "isp": connection.get("isp"),
            "note": (
                "Reverse DNS and network ownership are public-network "
                "indicators. They do not represent a complete list of "
                "every website that may use this IP."
            ),
        },
        "source": "Public IP intelligence lookup",
    }


class SelfProtectionIPLookupView(APIView):

    permission_classes = [
        IsAuthenticated
    ]

    def post(
        self,
        request,
    ):
        raw_ipv4 = str(
            request.data.get(
                "ipv4",
                "",
            )
        ).strip()

        if not raw_ipv4:
            return Response(
                {
                    "detail": "ipv4 is required."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            lookup = _lookup_public_ip(
                raw_ipv4
            )
        except ValueError as exc:
            return Response(
                {
                    "detail": str(exc)
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except requests.RequestException as exc:
            return Response(
                {
                    "detail": (
                        "IP intelligence service is temporarily unavailable."
                    ),
                    "provider_error": str(exc),
                },
                status=status.HTTP_502_BAD_GATEWAY,
            )

        return Response(
            {
                "message": "IPv4 self-protection lookup completed.",
                "lookup": lookup,
                "ipv6_policy": {
                    "editable": False,
                    "mode": "device_observed",
                    "description": (
                        "IPv6 is displayed from the current device/network "
                        "when available. A real IPv6 address cannot be "
                        "mathematically derived from an arbitrary IPv4 address."
                    ),
                },
            },
            status=status.HTTP_200_OK,
        )


class MalwareAnalyzeView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    @transaction.atomic
    def post(self, request):
        uploaded = request.FILES.get("file")
        if uploaded is None:
            return Response({"detail": "file is required."}, status=status.HTTP_400_BAD_REQUEST)
        if uploaded.size <= 0:
            return Response({"detail": "Uploaded file is empty."}, status=status.HTTP_400_BAD_REQUEST)
        if uploaded.size > MAX_MALWARE_UPLOAD_SIZE:
            return Response(
                {
                    "detail": "File is too large. Maximum allowed upload size is 200 MB.",
                    "max_size_mb": 200,
                    "file_size_mb": round(uploaded.size / (1024 * 1024), 2),
                },
                status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )

        suffix = os.path.splitext(uploaded.name)[1].lower()
        temp_path = None
        try:
            temp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
            temp_path = temp.name
            for chunk in uploaded.chunks():
                temp.write(chunk)
            temp.close()
            result = analyze_malware_file(temp_path, uploaded.name, uploaded.size)
            if not result.get("is_valid"):
                return Response(result, status=status.HTTP_400_BAD_REQUEST)

            score = _safe_float(result.get("risk_score", 0))
            severity = str(result.get("severity", "SAFE")).upper()
            threat = Threat.objects.create(
                user=request.user,
                threat_type="MALICIOUS_FILE",
                source_type="FILE",
                input_data=json.dumps({
                    "file_name": uploaded.name,
                    "file_size": uploaded.size,
                    "prediction": result.get("prediction"),
                    "model": result.get("features", {}).get("model"),
                }, ensure_ascii=False),
                risk_score=score,
                severity=severity if severity in dict(Threat.SEVERITY_CHOICES) else "SAFE",
                status="DETECTED",
                explanation=str(result.get("recommendation", "EMBER malware analysis completed.")),
            )
            _save_model_result(threat, "EMBER_MALWARE_ENGINE", result)
            incident = _create_incident(threat, ["Quarantine suspicious content", "Alert administrator"] if score >= 60 else [])
            return Response({
                **result,
                "threat_id": threat.id,
                "incident": ({
                    "id": incident.id,
                    "severity": incident.severity,
                    "status": incident.status,
                } if incident else None),
            }, status=status.HTTP_200_OK)
        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
# ============================================================================
# INCIDENT CREATION
# ============================================================================


def _create_incident(
    threat: Threat,
    recommended_actions: list[str],
) -> Incident | None:
    """
    Automatically create an Incident for HIGH or CRITICAL threats.
    """

    if threat.severity not in {
        "HIGH",
        "CRITICAL",
    }:
        return None

    incident = Incident.objects.create(
        incident_type=threat.threat_type,
        title=(
            f"{threat.severity} "
            f"{threat.threat_type.replace('_', ' ').title()}"
        ),
        description=threat.explanation,
        severity=threat.severity,
        status="OPEN",
        risk_score=threat.risk_score,
        created_by=threat.user,
        source_type=threat.source_type,
        source_id=threat.id,
    )

    # ----------------------------------------------------------------------
    # Copy threat evidence into incident evidence
    # ----------------------------------------------------------------------

    threat_evidence = list(
        threat.evidence.all()
    )

    incident_evidence = []

    for evidence in threat_evidence:

        incident_evidence.append(
            IncidentEvidence(
                incident=incident,
                evidence_type=evidence.evidence_type,
                evidence_value=evidence.evidence_value,
                risk_contribution=evidence.risk_contribution,
            )
        )

    if incident_evidence:

        IncidentEvidence.objects.bulk_create(
            incident_evidence
        )

    # ----------------------------------------------------------------------
    # Recommended action -> ResponseAction
    # ----------------------------------------------------------------------

    action_mapping = {
        "Block suspicious resource": "BLOCK_URL",
        "Quarantine suspicious content": "QUARANTINE_EMAIL",
        "Revoke active sessions": "REVOKE_SESSION",
        "Strengthen authentication": "STRENGTHEN_AUTH",
        "Alert user": "ALERT_USER",
        "Alert administrator": "ALERT_ADMIN",
        "Escalate incident": "ESCALATE",
        "Monitor": "MONITOR",
        "Continue monitoring": "MONITOR",
        "Increase monitoring": "MONITOR",
        "Request additional verification": "STRENGTHEN_AUTH",
        "Alert user if behaviour continues": "ALERT_USER",
    }

    for action in recommended_actions:

        action_type = action_mapping.get(
            action
        )

        if not action_type:
            continue

        ResponseAction.objects.create(
            incident=incident,
            action_type=action_type,
            description=(
                "Recommended by automated threat analysis: "
                f"{action}"
            ),
        )

    return incident


# ============================================================================
# THREAT LIST / CREATE
# ============================================================================


class ThreatListCreateView(
    generics.ListCreateAPIView
):
    serializer_class = ThreatSerializer

    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):

        return Threat.objects.filter(
            user=self.request.user
        ).order_by(
            "-detected_at"
        )

    def perform_create(
        self,
        serializer,
    ):

        threat = serializer.save(
            user=self.request.user
        )

        AuditLog.objects.create(
            user=self.request.user,
            action="THREAT_CREATED",
            ip_address=get_client_ip(
                self.request
            ),
            user_agent=self.request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"Threat created: "
                f"{threat.threat_type}"
            ),
            status="SUCCESS",
        )


# ============================================================================
# THREAT DETAIL / UPDATE
# ============================================================================


class ThreatDetailView(
    generics.RetrieveUpdateAPIView
):
    serializer_class = ThreatSerializer

    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):

        return Threat.objects.filter(
            user=self.request.user
        )

    def perform_update(
        self,
        serializer,
    ):

        threat = serializer.save()

        AuditLog.objects.create(
            user=self.request.user,
            action="THREAT_UPDATED",
            ip_address=get_client_ip(
                self.request
            ),
            user_agent=self.request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"Threat updated: "
                f"{threat.id}"
            ),
            status="SUCCESS",
        )


# ============================================================================
# MAIN AI THREAT ANALYSIS API
# ============================================================================


class ThreatAnalyzeView(
    APIView
):
    permission_classes = [
        IsAuthenticated
    ]

    @transaction.atomic
    def post(
        self,
        request,
    ):
        # ------------------------------------------------------------------
        # 1. Read request
        # ------------------------------------------------------------------

        threat_type = request.data.get(
            "threat_type"
        )

        source_type = request.data.get(
            "source_type"
        )

        input_data = request.data.get(
            "input_data"
        )

        # ------------------------------------------------------------------
        # 2. Required-field validation
        # ------------------------------------------------------------------

        if not threat_type:

            return Response(
                {
                    "detail": (
                        "threat_type is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not source_type:

            return Response(
                {
                    "detail": (
                        "source_type is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if (
            input_data is None
            or input_data == ""
        ):

            return Response(
                {
                    "detail": (
                        "input_data is required."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ------------------------------------------------------------------
        # 3. Choice validation
        # ------------------------------------------------------------------

        valid_threat_types = dict(
            Threat.THREAT_TYPE_CHOICES
        )

        valid_source_types = dict(
            Threat.SOURCE_TYPE_CHOICES
        )

        if threat_type not in valid_threat_types:

            return Response(
                {
                    "detail": (
                        "Invalid threat_type."
                    ),
                    "allowed_values": list(
                        valid_threat_types.keys()
                    ),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if source_type not in valid_source_types:

            return Response(
                {
                    "detail": (
                        "Invalid source_type."
                    ),
                    "allowed_values": list(
                        valid_source_types.keys()
                    ),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ------------------------------------------------------------------
        # 4. Run detection engines
        # ------------------------------------------------------------------

        model_results = (
            _run_detection_engines(
                threat_type=threat_type,
                source_type=source_type,
                input_data=input_data,
            )
        )

        # ------------------------------------------------------------------
        # 4A. Unified multi-source correlation
        # ------------------------------------------------------------------

        correlation_signals = (
            _build_correlation_signals(
                model_results=model_results,
                request_data=request.data,
            )
        )

        correlation_result = None

        distinct_sources = (
            _get_distinct_correlation_sources(
                correlation_signals
            )
        )

       
        if len(distinct_sources) >= 2:

            try:

                correlation_result = (
                    correlate_threat_signals(
                        correlation_signals
                    )
                )

            except Exception:
               
                correlation_result = None

        # ------------------------------------------------------------------
        # 5. Prepare scores for central risk engine
        # ------------------------------------------------------------------

        score_inputs = {}

        for model_name, result in model_results:

            if not isinstance(
                result,
                dict,
            ):
                continue

            score = result.get(
                "risk_score",
                result.get(
                    "score",
                    0,
                ),
            )

            score_inputs[
                model_name
            ] = _safe_float(
                score
            )

        # ------------------------------------------------------------------
        # 6. Central risk calculation
        # ------------------------------------------------------------------

        risk = analyze_risk(
            score_inputs
        )

        risk_score = _safe_float(
            risk.get(
                "risk_score",
                0,
            )
        )

        severity = str(
            risk.get(
                "severity",
                "SAFE",
            )
        ).upper()

        if severity not in dict(
            Threat.SEVERITY_CHOICES
        ):
            severity = "SAFE"

        explanation = str(
            risk.get(
                "explanation",
                "",
            )
        )

        recommended_actions = risk.get(
            "recommended_actions",
            [],
        )

        if not isinstance(
            recommended_actions,
            list,
        ):
            recommended_actions = []

        

        if isinstance(
            correlation_result,
            dict,
        ):

            correlated_score = correlation_result.get(
                "risk_score",
                correlation_result.get(
                    "unified_risk_score",
                    correlation_result.get(
                        "score",
                        None,
                    ),
                ),
            )

            if correlated_score is not None:

                correlation_score = _safe_float(
                    correlated_score
                )

                # Use the correlation score as the final
                # score only when multiple sources exist.
                risk_score = correlation_score

                correlated_severity = correlation_result.get(
                    "severity"
                )

                if correlated_severity:

                    correlated_severity = str(
                        correlated_severity
                    ).upper()

                    if correlated_severity in dict(
                        Threat.SEVERITY_CHOICES
                    ):
                        severity = correlated_severity

                correlation_explanation = (
                    correlation_result.get(
                        "explanation"
                    )
                )

                if correlation_explanation:

                    correlation_explanation = str(
                        correlation_explanation
                    )

                    if explanation:

                        explanation = (
                            f"{explanation} "
                            f"Correlation analysis: "
                            f"{correlation_explanation}"
                        )

                    else:

                        explanation = (
                            f"Correlation analysis: "
                            f"{correlation_explanation}"
                        )

        # ------------------------------------------------------------------
        # 7. Add detailed indicators
        # ------------------------------------------------------------------

        indicators = _unique_indicators(
            model_results
        )

        # Also collect indicators from correlation result.
        if isinstance(
            correlation_result,
            dict,
        ):

            correlation_indicators = (
                correlation_result.get(
                    "indicators",
                    [],
                )
            )

            if not isinstance(
                correlation_indicators,
                list,
            ):
                correlation_indicators = []

            for indicator in correlation_indicators:

                if indicator is None:
                    continue

                text = str(
                    indicator
                ).strip()

                if not text:
                    continue

                if text not in indicators:
                    indicators.append(text)

        if indicators:

            indicator_text = "; ".join(
                indicators[:10]
            )

            if explanation:

                explanation = (
                    f"{explanation} "
                    f"Key indicators: "
                    f"{indicator_text}"
                )

            else:

                explanation = (
                    "Security indicators detected: "
                    f"{indicator_text}"
                )

        # ------------------------------------------------------------------
        # 8. Create Threat
        # ------------------------------------------------------------------

        threat = Threat.objects.create(
            user=request.user,
            threat_type=threat_type,
            source_type=source_type,
            input_data=_stringify_input(
                input_data
            ),
            risk_score=risk_score,
            severity=severity,
            status="DETECTED",
            explanation=explanation,
        )

        # ------------------------------------------------------------------
        # 9. Save each engine result
        # ------------------------------------------------------------------

        for model_name, result in model_results:

            _save_model_result(
                threat=threat,
                model_name=model_name,
                result=result,
            )

        # ------------------------------------------------------------------
        # 9A. Save correlation evidence
        # ------------------------------------------------------------------

        if isinstance(
            correlation_result,
            dict,
        ):

            correlation_evidence = (
                correlation_result.get(
                    "evidence",
                    [],
                )
            )

            if not isinstance(
                correlation_evidence,
                list,
            ):
                correlation_evidence = []

            evidence_objects = []

            for evidence in correlation_evidence:

                if isinstance(
                    evidence,
                    dict,
                ):

                    evidence_value = evidence.get(
                        "evidence",
                        evidence.get(
                            "value",
                            evidence.get(
                                "description",
                                "",
                            ),
                        ),
                    )

                    evidence_type = evidence.get(
                        "type",
                        "CORRELATION",
                    )

                    contribution = evidence.get(
                        "risk_contribution",
                        risk_score,
                    )

                else:

                    evidence_value = evidence
                    evidence_type = "CORRELATION"
                    contribution = risk_score

                if evidence_value is None:
                    continue

                evidence_text = str(
                    evidence_value
                ).strip()

                if not evidence_text:
                    continue

                evidence_objects.append(
                    ThreatEvidence(
                        threat=threat,
                        evidence_type=str(
                            evidence_type
                        )[:100],
                        evidence_value=evidence_text,
                        risk_contribution=_safe_float(
                            contribution
                        ),
                    )
                )

            if evidence_objects:

                ThreatEvidence.objects.bulk_create(
                    evidence_objects
                )

        # ------------------------------------------------------------------
        # 10. No dedicated engine
        # ------------------------------------------------------------------

        if not model_results:

            ThreatAnalysis.objects.create(
                threat=threat,
                model_name="ROUTER",
                model_version="1.0",
                prediction="NO_DEDICATED_ENGINE",
                confidence=0.0,
                score=0.0,
                analysis_result={
                    "message": (
                        "No dedicated detection "
                        "engine is currently mapped "
                        f"for source type "
                        f"{source_type}."
                    ),
                    "threat_type": threat_type,
                    "source_type": source_type,
                },
            )

        # ------------------------------------------------------------------
        # 11. Create incident for HIGH / CRITICAL
        # ------------------------------------------------------------------

        incident = _create_incident(
            threat=threat,
            recommended_actions=recommended_actions,
        )

        # ------------------------------------------------------------------
        # 12. Audit log
        # ------------------------------------------------------------------

        correlation_enabled = (
            correlation_result is not None
        )

        AuditLog.objects.create(
            user=request.user,
            action="THREAT_ANALYZED",
            ip_address=get_client_ip(
                request
            ),
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                "Threat analysis completed. "
                f"Threat ID: {threat.id}; "
                f"score={risk_score}; "
                f"severity={severity}; "
                f"engines={len(model_results)}; "
                f"correlation={correlation_enabled}"
            ),
            status="SUCCESS",
        )

        # ------------------------------------------------------------------
        # 13. Build response
        # ------------------------------------------------------------------

        if correlation_result is not None:

            correlation_response = (
                correlation_result
            )

        else:

            correlation_response = {
                "enabled": False,
                "reason": (
                    "Correlation requires "
                    "at least two distinct "
                    "threat sources."
                ),
                "sources": sorted(
                    distinct_sources
                ),
            }

        response_data = {
            "message": (
                "Threat analysis completed."
            ),
            "threat": ThreatSerializer(
                threat
            ).data,
            "analysis": {
                "risk_score": risk_score,
                "severity": severity,
                "explanation": explanation,
                "recommended_actions": (
                    recommended_actions
                ),
                "engines_used": [
                    name
                    for name, _ in model_results
                ],
                "indicator_count": len(
                    indicators
                ),
                "indicators": indicators,
                "correlation": correlation_response,
            },
        }

        if incident:

            response_data["incident"] = {
                "id": incident.id,
                "severity": incident.severity,
                "status": incident.status,
            }

        return Response(
            response_data,
            status=status.HTTP_201_CREATED,
        )


# ============================================================================
# THREAT DELETE
# ============================================================================


class ThreatDeleteView(
    generics.DestroyAPIView
):
    serializer_class = ThreatSerializer

    permission_classes = [
        IsAuthenticated
    ]

    def get_queryset(self):

        return Threat.objects.filter(
            user=self.request.user
        )

    def perform_destroy(
        self,
        instance,
    ):

        threat_id = instance.id

        instance.delete()

        AuditLog.objects.create(
            user=self.request.user,
            action="THREAT_DELETED",
            ip_address=get_client_ip(
                self.request
            ),
            user_agent=self.request.META.get(
                "HTTP_USER_AGENT",
                "",
            ),
            description=(
                f"Threat deleted. "
                f"Threat ID: {threat_id}"
            ),
            status="SUCCESS",
        )