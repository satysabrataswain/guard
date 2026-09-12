from django.utils import timezone

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from audit_logs.models import AuditLog

from .models import (
    Incident,
    IncidentEvidence,
    ResponseAction,
)

from .serializers import (
    IncidentSerializer,
    IncidentEvidenceSerializer,
    ResponseActionSerializer,
)


class IncidentListCreateView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        incidents = Incident.objects.filter(
            created_by=request.user
        ).order_by("-created_at")

        return Response(
            IncidentSerializer(
                incidents,
                many=True
            ).data
        )

    def post(self, request):

        serializer = IncidentSerializer(
            data=request.data
        )

        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )

        incident = serializer.save(
            created_by=request.user
        )

        AuditLog.objects.create(
            user=request.user,
            action="INCIDENT_CREATED",
            description=(
                f"Incident created: "
                f"{incident.title}"
            ),
            status="SUCCESS",
        )

        return Response(
            IncidentSerializer(incident).data,
            status=status.HTTP_201_CREATED
        )


class IncidentDetailView(APIView):

    permission_classes = [IsAuthenticated]

    def get_object(self, request, pk):

        try:
            return Incident.objects.get(
                pk=pk,
                created_by=request.user
            )

        except Incident.DoesNotExist:
            return None

    def get(self, request, pk):

        incident = self.get_object(
            request,
            pk
        )

        if not incident:
            return Response(
                {"detail": "Incident not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        return Response(
            IncidentSerializer(incident).data
        )

    def put(self, request, pk):

        incident = self.get_object(
            request,
            pk
        )

        if not incident:
            return Response(
                {"detail": "Incident not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = IncidentSerializer(
            incident,
            data=request.data
        )

        if serializer.is_valid():

            incident = serializer.save()

            AuditLog.objects.create(
                user=request.user,
                action="INCIDENT_UPDATED",
                description=(
                    f"Incident updated: "
                    f"{incident.title}"
                ),
                status="SUCCESS",
            )

            return Response(
                IncidentSerializer(
                    incident
                ).data
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )

    def patch(self, request, pk):

        incident = self.get_object(
            request,
            pk
        )

        if not incident:
            return Response(
                {"detail": "Incident not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = IncidentSerializer(
            incident,
            data=request.data,
            partial=True
        )

        if serializer.is_valid():

            incident = serializer.save()

            return Response(
                IncidentSerializer(
                    incident
                ).data
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


class IncidentDeleteView(APIView):

    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):

        try:
            incident = Incident.objects.get(
                pk=pk,
                created_by=request.user
            )

        except Incident.DoesNotExist:
            return Response(
                {"detail": "Incident not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        incident.delete()

        return Response(
            {"message": "Incident deleted."},
            status=status.HTTP_200_OK
        )


class IncidentEvidenceView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request, pk):

        try:
            incident = Incident.objects.get(
                pk=pk,
                created_by=request.user
            )

        except Incident.DoesNotExist:
            return Response(
                {"detail": "Incident not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = IncidentEvidenceSerializer(
            data=request.data
        )

        if serializer.is_valid():

            evidence = serializer.save(
                incident=incident
            )

            return Response(
                IncidentEvidenceSerializer(
                    evidence
                ).data,
                status=status.HTTP_201_CREATED
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


class ResponseActionView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request, pk):

        try:
            incident = Incident.objects.get(
                pk=pk,
                created_by=request.user
            )

        except Incident.DoesNotExist:
            return Response(
                {"detail": "Incident not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = ResponseActionSerializer(
            data=request.data
        )

        if serializer.is_valid():

            action = serializer.save(
                incident=incident
            )

            return Response(
                ResponseActionSerializer(
                    action
                ).data,
                status=status.HTTP_201_CREATED
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


class ExecuteResponseActionView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request, pk):

        try:
            action = ResponseAction.objects.get(
                pk=pk,
                incident__created_by=request.user
            )

        except ResponseAction.DoesNotExist:
            return Response(
                {"detail": "Response action not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        action.status = "EXECUTED"
        action.executed_by = request.user
        action.executed_at = timezone.now()
        action.save()

        return Response(
            ResponseActionSerializer(action).data
        )


class ResolveIncidentView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request, pk):

        try:
            incident = Incident.objects.get(
                pk=pk,
                created_by=request.user
            )

        except Incident.DoesNotExist:
            return Response(
                {"detail": "Incident not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        incident.status = "RESOLVED"
        incident.resolved_at = timezone.now()
        incident.save()

        AuditLog.objects.create(
            user=request.user,
            action="INCIDENT_RESOLVED",
            description=(
                f"Incident resolved: "
                f"{incident.title}"
            ),
            status="SUCCESS",
        )

        return Response(
            IncidentSerializer(incident).data
        )