# Create your views here.
from __future__ import annotations

from rest_framework import permissions, viewsets

from .models import Rule
from .serializers import RuleSerializer


class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Allow read-only access to authenticated users,
    but write access only to admin/superuser.
    """

    def has_permission(self, request, view) -> bool:
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated
        return request.user and request.user.is_staff


class RuleViewSet(viewsets.ModelViewSet):
    """
    CRUD API for detection rules.

    - Authenticated users: can list / retrieve
    - Admin users: can create / update / delete
    """

    queryset = Rule.objects.all().order_by("name")
    serializer_class = RuleSerializer
    permission_classes = [IsAdminOrReadOnly]
