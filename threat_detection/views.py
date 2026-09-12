from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Threat
from .serializers import ThreatSerializer

from audit_logs.models import AuditLog
from accounts.utils import get_client_ip


class ThreatListCreateView(generics.ListCreateAPIView):
    serializer_class = ThreatSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Threat.objects.filter(
            user=self.request.user
        ).order_by("-detected_at")

    def perform_create(self, serializer):
        threat = serializer.save(
            user=self.request.user
        )

        AuditLog.objects.create(
            user=self.request.user,
            action="THREAT_ANALYZED",
            ip_address=get_client_ip(
                self.request
            ),
            user_agent=self.request.META.get(
                "HTTP_USER_AGENT",
                ""
            ),
            description=(
                f"Threat created: "
                f"{threat.threat_type}"
            ),
            status="SUCCESS",
        )


class ThreatDetailView(
    generics.RetrieveUpdateAPIView
):
    serializer_class = ThreatSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Threat.objects.filter(
            user=self.request.user
        )

    def perform_update(self, serializer):
        threat = serializer.save()

        AuditLog.objects.create(
            user=self.request.user,
            action="THREAT_ANALYZED",
            ip_address=get_client_ip(
                self.request
            ),
            user_agent=self.request.META.get(
                "HTTP_USER_AGENT",
                ""
            ),
            description=(
                f"Threat updated: "
                f"{threat.id}"
            ),
            status="SUCCESS",
        )


class ThreatAnalyzeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        threat_type = request.data.get(
            "threat_type"
        )

        source_type = request.data.get(
            "source_type"
        )

        input_data = request.data.get(
            "input_data"
        )

        # -------------------------------
        # Required field validation
        # -------------------------------

        if not threat_type:
            return Response(
                {
                    "detail":
                    "threat_type is required."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not source_type:
            return Response(
                {
                    "detail":
                    "source_type is required."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not input_data:
            return Response(
                {
                    "detail":
                    "input_data is required."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # -------------------------------
        # Choice validation
        # -------------------------------

        valid_threat_types = dict(
            Threat.THREAT_TYPE_CHOICES
        )

        valid_source_types = dict(
            Threat.SOURCE_TYPE_CHOICES
        )

        if threat_type not in valid_threat_types:
            return Response(
                {
                    "detail":
                    "Invalid threat_type."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if source_type not in valid_source_types:
            return Response(
                {
                    "detail":
                    "Invalid source_type."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # -------------------------------
        # Temporary analysis
        # AI engine will be connected later
        # -------------------------------

        risk_score = 0
        severity = "SAFE"

        explanation = (
            "Threat analysis created successfully. "
            "AI engine will generate the actual "
            "risk score, severity and explanation."
        )

        # -------------------------------
        # Create threat
        # -------------------------------

        threat = Threat.objects.create(
            user=request.user,
            threat_type=threat_type,
            source_type=source_type,
            input_data=input_data,
            risk_score=risk_score,
            severity=severity,
            status="DETECTED",
            explanation=explanation,
        )

        # -------------------------------
        # Audit log
        # -------------------------------

        AuditLog.objects.create(
            user=request.user,
            action="THREAT_ANALYZED",
            ip_address=get_client_ip(
                request
            ),
            user_agent=request.META.get(
                "HTTP_USER_AGENT",
                ""
            ),
            description=(
                f"Threat analysis performed. "
                f"Threat ID: {threat.id}"
            ),
            status="SUCCESS",
        )

        # -------------------------------
        # Response
        # -------------------------------

        return Response(
            {
                "message":
                "Threat analysis completed.",

                "threat":
                ThreatSerializer(
                    threat
                ).data,
            },
            status=status.HTTP_201_CREATED,
        )


class ThreatDeleteView(
    generics.DestroyAPIView
):
    serializer_class = ThreatSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Threat.objects.filter(
            user=self.request.user
        )

    def perform_destroy(self, instance):
        threat_id = instance.id

        instance.delete()

        AuditLog.objects.create(
            user=self.request.user,
            action="THREAT_ANALYZED",
            ip_address=get_client_ip(
                self.request
            ),
            user_agent=self.request.META.get(
                "HTTP_USER_AGENT",
                ""
            ),
            description=(
                f"Threat deleted. "
                f"Threat ID: {threat_id}"
            ),
            status="SUCCESS",
        )
