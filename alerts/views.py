from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import Alert
from .serializers import AlertSerializer


class AlertViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """
    API for viewing and managing alerts.

    - GET /api/alerts/alerts/           -> list alerts
    - GET /api/alerts/alerts/{id}/      -> retrieve one alert
    - PATCH /api/alerts/alerts/{id}/    -> update fields like status

    Custom actions:
    - POST /api/alerts/alerts/{id}/ack/    -> mark alert as acknowledged
    - POST /api/alerts/alerts/{id}/close/  -> mark alert as closed
    """

    serializer_class = AlertSerializer

    def get_queryset(self):
        qs = Alert.objects.select_related("rule", "machine").all()

        severity = self.request.query_params.get("severity")
        status_param = self.request.query_params.get("status")
        machine_id = self.request.query_params.get("machine")
        rule_id = self.request.query_params.get("rule")
        source_ip = self.request.query_params.get("source_ip")

        if severity:
            qs = qs.filter(severity=severity)
        if status_param:
            qs = qs.filter(status=status_param)
        if machine_id:
            qs = qs.filter(machine_id=machine_id)
        if rule_id:
            qs = qs.filter(rule_id=rule_id)
        if source_ip:
            qs = qs.filter(source_ip=source_ip)

        return qs

    @action(detail=True, methods=["post"])
    def ack(self, request, pk=None):
        """
        Mark an alert as acknowledged.
        """
        alert = self.get_object()
        alert.mark_acknowledged()
        serializer = self.get_serializer(alert)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def close(self, request, pk=None):
        """
        Mark an alert as closed.
        """
        alert = self.get_object()
        alert.mark_closed()
        serializer = self.get_serializer(alert)
        return Response(serializer.data, status=status.HTTP_200_OK)
