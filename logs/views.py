# Create your views here.
from __future__ import annotations

from django.utils import timezone
from rest_framework import permissions, status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView

from machines.models import Machine
from .models import LogEntry
from .serializers import LogEntryIngestionSerializer, LogEntrySerializer


MACHINE_TOKEN_HEADER = "X-Machine-Token"


class LogIngestionAPIView(APIView):
    """
    Endpoint for agents to submit log entries.

    Authentication:
      - Uses a simple header-based machine token:
        X-Machine-Token: <api_token>

    This is intentionally simple and explicit for now; we can later
    evolve this into full JWT-based machine auth while keeping
    the same external contract for agents.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs) -> Response:
        # 1) Authenticate machine via X-Machine-Token
        token = request.headers.get(MACHINE_TOKEN_HEADER)
        if not token:
            return Response(
                {"detail": f"Missing {MACHINE_TOKEN_HEADER} header."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            machine = Machine.objects.get(api_token=token, is_active=True)
        except Machine.DoesNotExist:
            return Response(
                {"detail": "Invalid or inactive machine token."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Update heartbeat
        machine.last_heartbeat = timezone.now()
        machine.save(update_fields=["last_heartbeat", "updated_at"])

        # 2) Validate payload (single event for now)
        serializer = LogEntryIngestionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        log_entry = LogEntryIngestionSerializer.create_entry(
            machine=machine, validated_data=serializer.validated_data
        )

        # TODO (Day 7–8): call rule engine with this log_entry

        return Response(
            {"id": str(log_entry.id), "status": "ingested"},
            status=status.HTTP_201_CREATED,
        )


class LogEntryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only API for browsing log entries (for human admins / dashboards).

    Uses standard DRF auth (JWT) and admin permissions.
    """

    queryset = LogEntry.objects.select_related("machine").order_by("-timestamp")
    serializer_class = LogEntrySerializer
    permission_classes = [permissions.IsAuthenticated]
