from django.utils import timezone
from datetime import timedelta

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from audit_logs.models import AuditLog

from .models import (
    UserBehaviour,
    LoginActivity,
    Anomaly,
)

from .serializers import (
    UserBehaviourSerializer,
    LoginActivitySerializer,
    AnomalySerializer,
)


def get_severity(score):
    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    if score >= 20:
        return "LOW"

    return "SAFE"


def get_client_ip(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.META.get("REMOTE_ADDR")


def analyse_login_anomaly(
    user,
    ip_address=None,
    device_id="",
    location="",
):
    score = 0
    indicators = []

    recent_time = timezone.now() - timedelta(hours=24)

    recent_logins = LoginActivity.objects.filter(
        user=user,
        created_at__gte=recent_time,
    )

    failed_count = recent_logins.filter(
        status="FAILED"
    ).count()

    if failed_count >= 3:
        score += 25

        indicators.append(
            "Multiple failed login attempts detected"
        )

    if failed_count >= 5:
        score += 20

        indicators.append(
            "High number of failed login attempts"
        )

    if ip_address:
        previous_ips = set(
            recent_logins.exclude(
                ip_address__isnull=True
            ).values_list(
                "ip_address",
                flat=True,
            )
        )

        if previous_ips and ip_address not in previous_ips:
            score += 20

            indicators.append(
                "Login from a previously unseen IP address"
            )

    if device_id:
        previous_devices = set(
            recent_logins.exclude(
                device_id=""
            ).values_list(
                "device_id",
                flat=True,
            )
        )

        if previous_devices and device_id not in previous_devices:
            score += 20

            indicators.append(
                "Login from a previously unseen device"
            )

    if location:
        previous_locations = set(
            recent_logins.exclude(
                location=""
            ).values_list(
                "location",
                flat=True,
            )
        )

        if previous_locations and location not in previous_locations:
            score += 15

            indicators.append(
                "Login from a previously unseen location"
            )

    score = min(score, 100)

    severity = get_severity(score)

    if indicators:
        explanation = "; ".join(indicators)
    else:
        explanation = "No significant abnormal behaviour detected"

    return score, severity, explanation, indicators


class AnalyseLoginView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        ip_address = request.data.get(
            "ip_address"
        ) or get_client_ip(request)

        device_id = request.data.get(
            "device_id",
            "",
        )

        location = request.data.get(
            "location",
            "",
        )

        user_agent = request.META.get(
            "HTTP_USER_AGENT",
            "",
        )

        score, severity, explanation, indicators = (
            analyse_login_anomaly(
                request.user,
                ip_address,
                device_id,
                location,
            )
        )

        LoginActivity.objects.create(
            user=request.user,
            ip_address=ip_address,
            user_agent=user_agent,
            location=location,
            device_id=device_id,
            status="SUCCESS",
        )

        anomaly = Anomaly.objects.create(
            user=request.user,
            anomaly_type="LOGIN_BEHAVIOUR",
            risk_score=score,
            severity=severity,
            explanation=explanation,
        )

        for indicator in indicators:
            UserBehaviour.objects.create(
                user=request.user,
                activity_type="LOGIN",
                ip_address=ip_address,
                user_agent=user_agent,
                location=location,
                device_id=device_id,
                activity_data={
                    "indicator": indicator,
                    "risk_contribution": 0,
                },
            )

        AuditLog.objects.create(
            user=request.user,
            action="ANOMALY_DETECTED",
            ip_address=ip_address,
            user_agent=user_agent,
            description=explanation,
            status="SUCCESS",
        )

        return Response(
            {
                "message": "Login behaviour analysed",
                "anomaly": AnomalySerializer(
                    anomaly
                ).data,
                "indicators": indicators,
            },
            status=status.HTTP_201_CREATED,
        )


class BehaviourCreateView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        serializer = UserBehaviourSerializer(
            data=request.data
        )

        if serializer.is_valid():

            behaviour = serializer.save(
                user=request.user
            )

            return Response(
                UserBehaviourSerializer(
                    behaviour
                ).data,
                status=status.HTTP_201_CREATED,
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )


class LoginActivityCreateView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        serializer = LoginActivitySerializer(
            data=request.data
        )

        if serializer.is_valid():

            activity = serializer.save(
                user=request.user
            )

            return Response(
                LoginActivitySerializer(
                    activity
                ).data,
                status=status.HTTP_201_CREATED,
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )


class AnomalyHistoryView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        anomalies = Anomaly.objects.filter(
            user=request.user
        ).order_by(
            "-detected_at"
        )

        serializer = AnomalySerializer(
            anomalies,
            many=True,
        )

        return Response(
            serializer.data,
            status=status.HTTP_200_OK,
        )


class AnomalyDetailView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request, pk):

        try:
            anomaly = Anomaly.objects.get(
                pk=pk,
                user=request.user,
            )

        except Anomaly.DoesNotExist:

            return Response(
                {
                    "detail": "Anomaly not found."
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response(
            AnomalySerializer(anomaly).data,
            status=status.HTTP_200_OK,
        )


class BehaviourHistoryView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        records = UserBehaviour.objects.filter(
            user=request.user
        ).order_by(
            "-created_at"
        )

        return Response(
            UserBehaviourSerializer(
                records,
                many=True,
            ).data
        )


class LoginHistoryView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        records = LoginActivity.objects.filter(
            user=request.user
        ).order_by(
            "-created_at"
        )

        return Response(
            LoginActivitySerializer(
                records,
                many=True,
            ).data
        )