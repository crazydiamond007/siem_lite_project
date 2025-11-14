# Create your views here.
from __future__ import annotations

from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import Alert, AlertStatus
from .serializers import AlertSerializer, AlertStatusUpdateSerializer


class AlertViewSet(viewsets.ModelViewSet):
    """
    API for listing and managing alerts.

    - Authenticated users: can list / retrieve
    - Admin users: can update status or delete
    """

    queryset = Alert.objects.select_related("machine", "rule").order_by("-first_seen")
    serializer_class = AlertSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.action in {"update", "partial_update"}:
            return AlertStatusUpdateSerializer
        return super().get_serializer_class()

    def update(self, request, *args, **kwargs):
        """
        Only allow updating status via PUT/PATCH.
        """
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = AlertStatusUpdateSerializer(
            instance, data=request.data, partial=partial
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(AlertSerializer(instance).data)

    @action(detail=True, methods=["post"])
    def resolve(self, request, pk=None):
        """
        Convenience action to mark an alert as resolved.
        """
        alert = self.get_object()
        alert.status = AlertStatus.RESOLVED
        alert.save(update_fields=["status", "updated_at"])
        return Response(AlertSerializer(alert).data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def acknowledge(self, request, pk=None):
        """
        Convenience action to mark an alert as acknowledged.
        """
        alert = self.get_object()
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.save(update_fields=["status", "updated_at"])
        return Response(AlertSerializer(alert).data, status=status.HTTP_200_OK)
