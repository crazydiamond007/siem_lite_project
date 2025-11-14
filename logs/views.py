from __future__ import annotations

from django.utils import timezone
from rest_framework import permissions, status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView

from machines.auth import (
    MachineTokenError,
    authenticate_machine_from_jwt,
)
from machines.models import Machine
from .models import LogEntry
from .serializers import LogEntryIngestionSerializer, LogEntrySerializer
from rules.engine import apply_rules_to_log_entry


MACHINE_TOKEN_HEADER = "X-Machine-Token"


def _get_machine_from_request(request) -> Machine | None:
    """
    Resolve a Machine from the incoming request using one of:
      1) Authorization: Bearer <machine_jwt>  (preferred)
      2) X-Machine-Token: <api_token>        (fallback)
    """
    auth_header = request.headers.get("Authorization", "")
    token_prefix = "Bearer "

    # 1) Try Authorization: Bearer <machine_jwt>
    if auth_header.startswith(token_prefix):
        jwt_token = auth_header[len(token_prefix) :].strip()
        if jwt_token:
            try:
                machine = authenticate_machine_from_jwt(jwt_token)
                return machine
            except MachineTokenError:
                # Fall through to header-based token as fallback
                pass

    # 2) Fallback to X-Machine-Token (long-lived api_token)
    api_token = request.headers.get(MACHINE_TOKEN_HEADER)
    if api_token:
        try:
            return Machine.objects.get(api_token=api_token, is_active=True)
        except Machine.DoesNotExist:
            return None

    return None


class LogIngestionAPIView(APIView):
    """
    Endpoint for agents to submit log entries.

    Authentication (machine-level):

      Preferred:
        Authorization: Bearer <machine_jwt>

      Backward compatible:
        X-Machine-Token: <api_token>

    Note:
      We disable DRF's default authentication (SimpleJWT user tokens) here,
      because we manage machine authentication manually.
    """

    # VERY IMPORTANT: disable default JWTAuthentication for this endpoint
    authentication_classes: list = []
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs) -> Response:
        # 1) Authenticate machine
        machine = _get_machine_from_request(request)
        if not machine:
            return Response(
                {
                    "detail": (
                        "Unable to authenticate machine. Provide either "
                        "Authorization: Bearer <machine_jwt> or "
                        f"{MACHINE_TOKEN_HEADER}: <api_token>."
                    )
                },
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

        # 3) Apply detection rules (basic rule engine)
        apply_rules_to_log_entry(log_entry)

        return Response(
            {"id": str(log_entry.id), "status": "ingested"},
            status=status.HTTP_201_CREATED,
        )


class LogEntryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only API for browsing log entries (for human admins / dashboards).
    """

    queryset = LogEntry.objects.select_related("machine").order_by("-timestamp")
    serializer_class = LogEntrySerializer
    permission_classes = [permissions.IsAuthenticated]
