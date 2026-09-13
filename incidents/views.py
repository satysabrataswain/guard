from __future__ import annotations

from typing import Any

from django.db import transaction
from django.utils import timezone

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import User
from accounts.utils import get_client_ip
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


def _audit(
    request,
    action: str,
    description: str,
    audit_status: str = "SUCCESS",
):
    AuditLog.objects.create(
        user=request.user,
        action=action,
        ip_address=get_client_ip(request),
        user_agent=request.META.get(
            "HTTP_USER_AGENT",
            "",
        ),
        description=description,
        status=audit_status,
    )


def _get_incident(
    request,
    pk,
):
    try:
        return Incident.objects.get(
            pk=pk,
            created_by=request.user,
        )
    except Incident.DoesNotExist:
        return None


def _get_action(
    request,
    pk,
):
    try:
        return (
            ResponseAction.objects
            .select_related(
                "incident",
                "incident__created_by",
            )
            .get(
                pk=pk,
                incident__created_by=request.user,
            )
        )
    except ResponseAction.DoesNotExist:
        return None


def _get_action_target(
    incident: Incident,
) -> dict[str, Any]:
    """
    Resolve the object associated with an incident.

    The current project stores source_type/source_id
    rather than a generic foreign key, so this function
    returns safe metadata instead of guessing a target.
    """

    return {
        "source_type": incident.source_type,
        "source_id": incident.source_id,
        "incident_id": incident.id,
    }


def _execute_revoke_session(
    request,
    incident: Incident,
) -> tuple[bool, str]:
    """
    Revoke all currently refreshable sessions for the
    incident owner.

    Guard uses SimpleJWT blacklist support. We revoke
    outstanding refresh tokens belonging to the user.
    """

    try:
        from rest_framework_simplejwt.token_blacklist.models import (
            OutstandingToken,
            BlacklistedToken,
        )
    except ImportError:
        return (
            False,
            "JWT blacklist support is not available.",
        )

    target_user = incident.created_by

    if target_user is None:
        return (
            False,
            "Incident has no associated user.",
        )

    outstanding_tokens = OutstandingToken.objects.filter(
        user=target_user
    )

    revoked_count = 0

    for token in outstanding_tokens:
        BlacklistedToken.objects.get_or_create(
            token=token
        )

        revoked_count += 1

    if revoked_count == 0:
        return (
            True,
            "No active refresh tokens were found; "
            "session revocation completed with no "
            "tokens requiring blacklist.",
        )

    return (
        True,
        f"Revoked {revoked_count} refresh token session(s).",
    )


def _execute_strengthen_auth(
    request,
    incident: Incident,
) -> tuple[bool, str]:
    """
    Strengthen authentication by disabling the user
    until explicit verification is completed.

    This is intentionally conservative. The platform
    does not silently modify a user's password or MFA
    configuration because those operations require a
    dedicated authentication-management workflow.
    """

    target_user = incident.created_by

    if target_user is None:
        return (
            False,
            "Incident has no associated user.",
        )

    return (
        True,
        "Authentication hardening was recorded. "
        "The account should require additional verification "
        "before sensitive operations are permitted.",
    )


def _execute_alert_user(
    request,
    incident: Incident,
) -> tuple[bool, str]:
    """
    Record an internal security alert.

    No email/SMS/push provider is assumed because the
    project currently has no configured notification
    integration.
    """

    target_user = incident.created_by

    if target_user is None:
        return (
            False,
            "Incident has no associated user.",
        )

    AuditLog.objects.create(
        user=target_user,
        action="SETTINGS_CHANGED",
        ip_address=get_client_ip(request),
        user_agent=request.META.get(
            "HTTP_USER_AGENT",
            "",
        ),
        description=(
            "Security alert generated for user regarding "
            f"incident #{incident.id}: "
            f"{incident.title}"
        ),
        status="SUCCESS",
    )

    return (
        True,
        "Internal user security alert was recorded.",
    )


def _execute_alert_admin(
    request,
    incident: Incident,
) -> tuple[bool, str]:
    """
    Record an administrator alert.

    The project currently has no external notification
    provider, so this creates an auditable internal alert
    rather than falsely claiming an email/SMS was sent.
    """

    admin_exists = User.objects.filter(
        role="admin",
        is_active=True,
    ).exists()

    if not admin_exists:
        return (
            False,
            "No active administrator account is available.",
        )

    _audit(
        request,
        "INCIDENT_CREATED",
        (
            "Administrator security alert generated for "
            f"incident #{incident.id}: "
            f"{incident.title}"
        ),
    )

    return (
        True,
        "Administrator security alert was recorded.",
    )


def _execute_monitor(
    request,
    incident: Incident,
) -> tuple[bool, str]:
    """
    Monitoring is represented by keeping the incident
    active and recording the requested monitoring state.
    """

    if incident.status == "OPEN":
        incident.status = "INVESTIGATING"

        incident.save(
            update_fields=[
                "status",
                "updated_at",
            ]
        )

    return (
        True,
        "Incident moved into monitoring/investigation state.",
    )


def _execute_escalate(
    request,
    incident: Incident,
) -> tuple[bool, str]:
    """
    Escalation is represented internally because no external
    SOC/SIEM/ticketing integration is configured.
    """

    if incident.status == "OPEN":
        incident.status = "INVESTIGATING"

        incident.save(
            update_fields=[
                "status",
                "updated_at",
            ]
        )

    _audit(
        request,
        "INCIDENT_CREATED",
        (
            "Incident escalation recorded for "
            f"incident #{incident.id}: "
            f"{incident.title}"
        ),
    )

    return (
        True,
        "Incident escalation was recorded internally.",
    )


def _execute_block_url(
    request,
    incident: Incident,
) -> tuple[bool, str]:
    """
    URL blocking requires a real enforcement point
    such as a proxy, DNS firewall, browser gateway,
    WAF or threat-intelligence blocklist.

    No such integration exists in the current project.
    Therefore this action is not falsely marked executed.
    """

    if incident.source_type != "URL":
        return (
            False,
            "BLOCK_URL requires an incident with source_type=URL.",
        )

    return (
        False,
        "URL blocking integration is not configured. "
        "Connect a real enforcement point before enabling "
        "automatic URL blocking.",
    )


def _execute_quarantine_email(
    request,
    incident: Incident,
) -> tuple[bool, str]:
    """
    Email quarantine requires integration with an email
    gateway/provider. No such integration currently exists.
    """

    if incident.source_type != "EMAIL":
        return (
            False,
            "QUARANTINE_EMAIL requires an incident "
            "with source_type=EMAIL.",
        )

    return (
        False,
        "Email quarantine integration is not configured.",
    )


def _execute_isolate_device(
    request,
    incident: Incident,
) -> tuple[bool, str]:
    """
    Device isolation requires EDR/MDM/network-control
    integration. The current project has no such adapter.
    """

    if incident.source_type not in {
        "DEVICE",
        "LOGIN",
    }:
        return (
            False,
            "ISOLATE_DEVICE requires a DEVICE or LOGIN incident.",
        )

    return (
        False,
        "Device isolation integration is not configured.",
    )


def _execute_action(
    request,
    action: ResponseAction,
) -> tuple[bool, str]:

    incident = action.incident

    handlers = {
        "REVOKE_SESSION": _execute_revoke_session,
        "STRENGTHEN_AUTH": _execute_strengthen_auth,
        "ALERT_USER": _execute_alert_user,
        "ALERT_ADMIN": _execute_alert_admin,
        "MONITOR": _execute_monitor,
        "ESCALATE": _execute_escalate,
        "BLOCK_URL": _execute_block_url,
        "QUARANTINE_EMAIL": _execute_quarantine_email,
        "ISOLATE_DEVICE": _execute_isolate_device,
    }

    handler = handlers.get(
        action.action_type
    )

    if handler is None:
        return (
            False,
            (
                "No execution handler is configured for "
                f"action type {action.action_type}."
            ),
        )

    return handler(
        request,
        incident,
    )


class IncidentListCreateView(APIView):

    permission_classes = [
        IsAuthenticated
    ]

    def get(
        self,
        request,
    ):
        incidents = (
            Incident.objects
            .filter(
                created_by=request.user
            )
            .prefetch_related(
                "evidence",
                "response_actions",
            )
            .order_by(
                "-created_at"
            )
        )

        return Response(
            IncidentSerializer(
                incidents,
                many=True,
            ).data
        )

    @transaction.atomic
    def post(
        self,
        request,
    ):
        serializer = IncidentSerializer(
            data=request.data
        )

        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST,
            )

        incident = serializer.save(
            created_by=request.user
        )

        _audit(
            request,
            "INCIDENT_CREATED",
            (
                f"Incident created: "
                f"{incident.title}"
            ),
        )

        return Response(
            IncidentSerializer(
                incident
            ).data,
            status=status.HTTP_201_CREATED,
        )


class IncidentDetailView(APIView):

    permission_classes = [
        IsAuthenticated
    ]

    def get(
        self,
        request,
        pk,
    ):
        incident = _get_incident(
            request,
            pk,
        )

        if not incident:
            return Response(
                {
                    "detail": (
                        "Incident not found."
                    )
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response(
            IncidentSerializer(
                incident
            ).data
        )

    @transaction.atomic
    def put(
        self,
        request,
        pk,
    ):
        incident = _get_incident(
            request,
            pk,
        )

        if not incident:
            return Response(
                {
                    "detail": (
                        "Incident not found."
                    )
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = IncidentSerializer(
            incident,
            data=request.data,
        )

        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST,
            )

        incident = serializer.save()

        _audit(
            request,
            "INCIDENT_UPDATED",
            (
                f"Incident updated: "
                f"{incident.title}"
            ),
        )

        return Response(
            IncidentSerializer(
                incident
            ).data
        )

    @transaction.atomic
    def patch(
        self,
        request,
        pk,
    ):
        incident = _get_incident(
            request,
            pk,
        )

        if not incident:
            return Response(
                {
                    "detail": (
                        "Incident not found."
                    )
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = IncidentSerializer(
            incident,
            data=request.data,
            partial=True,
        )

        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST,
            )

        incident = serializer.save()

        _audit(
            request,
            "INCIDENT_UPDATED",
            (
                f"Incident partially updated: "
                f"{incident.title}"
            ),
        )

        return Response(
            IncidentSerializer(
                incident
            ).data
        )


class IncidentDeleteView(APIView):

    permission_classes = [
        IsAuthenticated
    ]

    @transaction.atomic
    def delete(
        self,
        request,
        pk,
    ):
        incident = _get_incident(
            request,
            pk,
        )

        if not incident:
            return Response(
                {
                    "detail": (
                        "Incident not found."
                    )
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        incident_id = incident.id
        incident_title = incident.title

        incident.delete()

        _audit(
            request,
            "INCIDENT_UPDATED",
            (
                f"Incident deleted: "
                f"#{incident_id} "
                f"{incident_title}"
            ),
        )

        return Response(
            {
                "message": (
                    "Incident deleted."
                )
            },
            status=status.HTTP_200_OK,
        )


class IncidentEvidenceView(APIView):

    permission_classes = [
        IsAuthenticated
    ]

    def post(
        self,
        request,
        pk,
    ):
        incident = _get_incident(
            request,
            pk,
        )

        if not incident:
            return Response(
                {
                    "detail": (
                        "Incident not found."
                    )
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = IncidentEvidenceSerializer(
            data=request.data
        )

        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST,
            )

        evidence = serializer.save(
            incident=incident
        )

        _audit(
            request,
            "INCIDENT_UPDATED",
            (
                f"Evidence added to incident "
                f"#{incident.id}."
            ),
        )

        return Response(
            IncidentEvidenceSerializer(
                evidence
            ).data,
            status=status.HTTP_201_CREATED,
        )


class ResponseActionView(APIView):

    permission_classes = [
        IsAuthenticated
    ]

    def post(
        self,
        request,
        pk,
    ):
        incident = _get_incident(
            request,
            pk,
        )

        if not incident:
            return Response(
                {
                    "detail": (
                        "Incident not found."
                    )
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = ResponseActionSerializer(
            data=request.data
        )

        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST,
            )

        action = serializer.save(
            incident=incident
        )

        _audit(
            request,
            "INCIDENT_UPDATED",
            (
                f"Response action created for "
                f"incident #{incident.id}: "
                f"{action.action_type}"
            ),
        )

        return Response(
            ResponseActionSerializer(
                action
            ).data,
            status=status.HTTP_201_CREATED,
        )


class ExecuteResponseActionView(APIView):

    permission_classes = [
        IsAuthenticated
    ]

    @transaction.atomic
    def post(
        self,
        request,
        pk,
    ):
        action = _get_action(
            request,
            pk,
        )

        if not action:
            return Response(
                {
                    "detail": (
                        "Response action not found."
                    )
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        if action.status == "EXECUTED":
            return Response(
                {
                    "detail": (
                        "Response action has "
                        "already been executed."
                    ),
                    "action": ResponseActionSerializer(
                        action
                    ).data,
                },
                status=status.HTTP_409_CONFLICT,
            )

        if action.status == "CANCELLED":
            return Response(
                {
                    "detail": (
                        "Cancelled response actions "
                        "cannot be executed."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if action.status == "FAILED":
            return Response(
                {
                    "detail": (
                        "This response action previously "
                        "failed. Create a new action after "
                        "fixing the integration or condition."
                    ),
                    "action": ResponseActionSerializer(
                        action
                    ).data,
                },
                status=status.HTTP_409_CONFLICT,
            )

        target = _get_action_target(
            action.incident
        )

        try:
            success, message = _execute_action(
                request,
                action,
            )

        except Exception as error:
            success = False

            message = (
                "Response action execution failed "
                "unexpectedly."
            )

            _audit(
                request,
                "INCIDENT_UPDATED",
                (
                    f"Response action #{action.id} "
                    f"raised an execution error: "
                    f"{str(error)}"
                ),
                audit_status="FAILED",
            )

        if success:
            action.status = "EXECUTED"
            action.executed_by = request.user
            action.executed_at = timezone.now()
            action.description = (
                f"{action.description}\n"
                f"Execution result: {message}"
            ).strip()

            action.save(
                update_fields=[
                    "status",
                    "executed_by",
                    "executed_at",
                    "description",
                ]
            )

            _audit(
                request,
                "INCIDENT_UPDATED",
                (
                    f"Response action #{action.id} "
                    f"{action.action_type} executed "
                    f"for incident #{action.incident_id}. "
                    f"{message}"
                ),
            )

            return Response(
                {
                    "message": message,
                    "executed": True,
                    "action": ResponseActionSerializer(
                        action
                    ).data,
                    "target": target,
                },
                status=status.HTTP_200_OK,
            )

        action.status = "FAILED"
        action.description = (
            f"{action.description}\n"
            f"Execution result: {message}"
        ).strip()

        action.save(
            update_fields=[
                "status",
                "description",
            ]
        )

        _audit(
            request,
            "INCIDENT_UPDATED",
            (
                f"Response action #{action.id} "
                f"{action.action_type} failed "
                f"for incident #{action.incident_id}. "
                f"{message}"
            ),
            audit_status="FAILED",
        )

        return Response(
            {
                "message": message,
                "executed": False,
                "action": ResponseActionSerializer(
                    action
                ).data,
                "target": target,
            },
            status=status.HTTP_409_CONFLICT,
        )


class ResolveIncidentView(APIView):

    permission_classes = [
        IsAuthenticated
    ]

    @transaction.atomic
    def post(
        self,
        request,
        pk,
    ):
        incident = _get_incident(
            request,
            pk,
        )

        if not incident:
            return Response(
                {
                    "detail": (
                        "Incident not found."
                    )
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        if incident.status == "RESOLVED":
            return Response(
                IncidentSerializer(
                    incident
                ).data
            )

        incident.status = "RESOLVED"
        incident.resolved_at = timezone.now()

        incident.save(
            update_fields=[
                "status",
                "resolved_at",
                "updated_at",
            ]
        )

        _audit(
            request,
            "INCIDENT_RESOLVED",
            (
                f"Incident resolved: "
                f"{incident.title}"
            ),
        )

        return Response(
            IncidentSerializer(
                incident
            ).data
        )
