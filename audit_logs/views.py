
from __future__ import annotations

from django.db.models import Q

from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from .models import AuditLog
from .serializers import AuditLogSerializer


class AuditLogListView(generics.ListAPIView):
    """
    Return audit logs visible to the current user.

    Normal users:
        Only their own audit events.

    Analysts/Admins:
        Can review the broader audit trail.

    The queryset is read-only through this API.
    """

    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user

        queryset = AuditLog.objects.select_related(
            "user"
        ).order_by(
            "-timestamp"
        )

        # ----------------------------------------------------
        # Normal users only see their own audit records.
        # ----------------------------------------------------

        if not getattr(user, "is_staff", False) and getattr(
            user,
            "role",
            "user",
        ) not in {
            "analyst",
            "admin",
        }:
            queryset = queryset.filter(
                user=user
            )

        # ----------------------------------------------------
        # Optional filters
        # ----------------------------------------------------

        action = self.request.query_params.get(
            "action"
        )

        status_value = self.request.query_params.get(
            "status"
        )

        resource = self.request.query_params.get(
            "resource"
        )

        resource_id = self.request.query_params.get(
            "resource_id"
        )

        user_id = self.request.query_params.get(
            "user_id"
        )

        search = self.request.query_params.get(
            "search"
        )

        if action:
            queryset = queryset.filter(
                action__iexact=action.strip()
            )

        if status_value:
            queryset = queryset.filter(
                status__iexact=status_value.strip()
            )

        if resource:
            queryset = queryset.filter(
                resource__iexact=resource.strip()
            )

        if resource_id:
            queryset = queryset.filter(
                resource_id=str(resource_id).strip()
            )

        # ----------------------------------------------------
        # user_id filter is restricted to privileged users.
        # ----------------------------------------------------

        if user_id:

            is_privileged = (
                getattr(user, "is_staff", False)
                or getattr(user, "role", "user")
                in {
                    "analyst",
                    "admin",
                }
            )

            if is_privileged:
                queryset = queryset.filter(
                    user__user_id=user_id.strip()
                )
            else:
                # A normal user must never be able to use
                # user_id filtering to inspect another user's
                # audit history.
                queryset = queryset.filter(
                    user=user
                )

        # ----------------------------------------------------
        # General search
        # ----------------------------------------------------

        if search:

            search = search.strip()

            if search:

                queryset = queryset.filter(
                    Q(action__icontains=search)
                    | Q(description__icontains=search)
                    | Q(resource__icontains=search)
                    | Q(resource_id__icontains=search)
                    | Q(ip_address__icontains=search)
                )

        return queryset


class AuditLogDetailView(generics.RetrieveAPIView):
    """
    Return a single audit record.

    Access is restricted so a normal user can only inspect
    their own audit events.
    """

    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):

        user = self.request.user

        queryset = AuditLog.objects.select_related(
            "user"
        )

        if getattr(user, "is_staff", False):
            return queryset

        if getattr(user, "role", "user") in {
            "analyst",
            "admin",
        }:
            return queryset

        return queryset.filter(
            user=user
        )


class MyAuditLogListView(generics.ListAPIView):
    """
    Explicit endpoint for the current user's audit history.

    This endpoint intentionally ignores arbitrary user_id
    query parameters.
    """

    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):

        return AuditLog.objects.filter(
            user=self.request.user
        ).select_related(
            "user"
        ).order_by(
            "-timestamp"
        )
