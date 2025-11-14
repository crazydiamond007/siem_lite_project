from __future__ import annotations

from rest_framework import permissions, status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView

from .auth import issue_machine_jwt
from .models import Machine
from .serializers import (
    MachineRegistrationResponseSerializer,
    MachineRegistrationSerializer,
    MachineSerializer,
)


class MachineRegistrationAPIView(APIView):
    """
    Public endpoint used by agents to register with the SIEM-Lite backend.

    Authentication: none (for now), but we could later protect it with a shared
    enrollment secret or IP whitelist.

    Agents receive a machine `id` and `api_token` which they must keep secret.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs) -> Response:
        serializer = MachineRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        machine = serializer.save()
        response_serializer = MachineRegistrationResponseSerializer(machine)

        return Response(response_serializer.data, status=status.HTTP_201_CREATED)


class MachineTokenAPIView(APIView):
    """
    Exchange a long-lived machine api_token for a short-lived JWT.

    Auth flow for agents:

      1) Register machine (once) → receive api_token.
      2) Call this endpoint with api_token (and optional machine_id) to obtain JWT.
      3) Use `Authorization: Bearer <machine_jwt>` when sending logs.

    This keeps the api_token mostly off the wire and allows us to rotate JWT lifetimes.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs) -> Response:
        api_token = request.data.get("api_token")
        machine_id = request.data.get("machine_id")

        if not api_token:
            return Response(
                {"detail": "Missing 'api_token' in request body."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            if machine_id:
                machine = Machine.objects.get(
                    id=machine_id, api_token=api_token, is_active=True
                )
            else:
                machine = Machine.objects.get(api_token=api_token, is_active=True)
        except Machine.DoesNotExist:
            return Response(
                {"detail": "Invalid api_token or machine inactive."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        access_token, expires_in = issue_machine_jwt(machine)

        return Response(
            {
                "access": access_token,
                "token_type": "machine",
                "expires_in": expires_in,
                "machine_id": str(machine.id),
            },
            status=status.HTTP_200_OK,
        )


class MachineViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only viewset for Machines, typically used by authenticated human admins.

    This uses the default DRF authentication (JWT via SimpleJWT for users).
    """

    queryset = Machine.objects.all().order_by("-created_at")
    serializer_class = MachineSerializer
    permission_classes = [permissions.IsAuthenticated]
