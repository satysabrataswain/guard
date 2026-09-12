from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import IsAdmin

from .models import AuditLog
from .serializers import AuditLogSerializer


class MyAuditLogView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        logs = AuditLog.objects.filter(
            user=request.user
        ).order_by("-created_at")

        serializer = AuditLogSerializer(
            logs,
            many=True,
        )

        return Response(
            serializer.data,
            status=status.HTTP_200_OK,
        )


class AdminAuditLogView(APIView):

    permission_classes = [
        IsAuthenticated,
        IsAdmin,
    ]

    def get(self, request):

        logs = AuditLog.objects.all().order_by(
            "-created_at"
        )

        serializer = AuditLogSerializer(
            logs,
            many=True,
        )

        return Response(
            serializer.data,
            status=status.HTTP_200_OK,
        )