from __future__ import annotations

from django.db.models import Q

from rest_framework import generics
from rest_framework.permissions import BasePermission, IsAuthenticated

from .models import AuditLog
from .serializers import AuditLogSerializer


class IsAuditAdmin(BasePermission):
    """
    Only staff users or users with the admin role can access
    the admin audit-log endpoint.
    """

    message = "Admin access required."

    def has_permission(self, request, view):
        user = request.user

        if not user or not user.is_authenticated:
            return False

        return bool(
            getattr(user, "is_staff", False)
            or getattr(user, "role", "user") == "admin"
        )


class AuditLogListView(generics.ListAPIView):
    """
    General audit-log endpoint.

    Admins and analysts can view all audit logs.
    Normal users can view only their own logs.
    """

    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user

        queryset = AuditLog.objects.select_related(
            "user"
        ).order_by(
            "-created_at"
        )

        # Normal users can only see their own audit logs.
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

        action = self.request.query_params.get("action")
        status_value = self.request.query_params.get("status")
        resource = self.request.query_params.get("resource")
        resource_id = self.request.query_params.get("resource_id")
        user_id = self.request.query_params.get("user_id")
        search = self.request.query_params.get("search")

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

        if user_id:
            is_privileged = (
                getattr(user, "is_staff", False)
                or getattr(user, "role", "user")
                in {"analyst", "admin"}
            )

            if is_privileged:
                queryset = queryset.filter(
                    user__user_id=user_id.strip()
                )
            else:
                queryset = queryset.filter(
                    user=user
                )

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
    View a single audit log.

    Staff/admin/analyst users can view any log.
    Normal users can view only their own logs.
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
    Return only the currently authenticated user's audit logs.
    """

    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return (
            AuditLog.objects
            .filter(user=self.request.user)
            .select_related("user")
            .order_by("-created_at")
        )


class AdminAuditLogListView(generics.ListAPIView):
    """
    Admin-only audit-log endpoint.

    Normal users and analysts are not allowed here.
    """

    serializer_class = AuditLogSerializer
    permission_classes = [IsAuditAdmin]

    def get_queryset(self):
        queryset = AuditLog.objects.select_related(
            "user"
        ).order_by(
            "-created_at"
        )

        action = self.request.query_params.get("action")
        status_value = self.request.query_params.get("status")
        resource = self.request.query_params.get("resource")
        resource_id = self.request.query_params.get("resource_id")
        user_id = self.request.query_params.get("user_id")
        search = self.request.query_params.get("search")

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

        if user_id:
            queryset = queryset.filter(
                user__user_id=user_id.strip()
            )

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