# Create your views here.
from __future__ import annotations

from rest_framework import permissions, status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Machine
from .serializers import (
    MachineSerializer,
    MachineRegistrationSerializer,
    MachineRegistrationResponseSerializer,
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


class MachineViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only viewset for Machines, typically used by authenticated human admins.

    This uses the default DRF authentication (JWT via SimpleJWT).
    """

    queryset = Machine.objects.all().order_by("-created_at")
    serializer_class = MachineSerializer
    permission_classes = [permissions.IsAuthenticated]
