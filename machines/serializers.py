from __future__ import annotations

from rest_framework import serializers

from .models import Machine


class MachineSerializer(serializers.ModelSerializer):
    """
    Read-only representation of a Machine for API consumers (mostly admins).
    """

    class Meta:
        model = Machine
        fields = [
            "id",
            "name",
            "hostname",
            "ip_address",
            "description",
            "is_active",
            "last_heartbeat",
            "registered_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class MachineRegistrationSerializer(serializers.Serializer):
    """
    Payload used when an agent registers itself for the first time.

    This keeps it simple and avoids exposing internal fields such as api_token.
    """

    name = serializers.CharField(
        max_length=150,
        help_text="Human-friendly name for this machine (e.g. 'web-01').",
    )
    hostname = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
        help_text="Optional hostname of the machine.",
    )
    ip_address = serializers.IPAddressField(
        required=False,
        allow_null=True,
        help_text="Optional IP address at registration time.",
    )

    def create(self, validated_data):
        return Machine.objects.create(
            name=validated_data["name"],
            hostname=validated_data.get("hostname", ""),
            ip_address=validated_data.get("ip_address"),
        )


class MachineRegistrationResponseSerializer(serializers.ModelSerializer):
    """
    Response sent back to the agent after registration.

    Includes the machine ID and the API token that will be used
    for authentication in ingestion calls.
    """

    class Meta:
        model = Machine
        fields = [
            "id",
            "name",
            "hostname",
            "ip_address",
            "api_token",
            "is_active",
            "registered_at",
        ]
        read_only_fields = fields
