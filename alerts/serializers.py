from __future__ import annotations

from rest_framework import serializers

from .models import Alert, AlertStatus


class AlertSerializer(serializers.ModelSerializer):
    """
    Read-only representation of an Alert for dashboards and APIs.
    """

    machine_name = serializers.CharField(source="machine.name", read_only=True)
    rule_name = serializers.CharField(source="rule.name", read_only=True)

    class Meta:
        model = Alert
        fields = [
            "id",
            "machine",
            "machine_name",
            "rule",
            "rule_name",
            "title",
            "message",
            "severity",
            "status",
            "source_ip",
            "first_seen",
            "last_seen",
            "occurrence_count",
            "deduplication_key",
            "metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "machine",
            "machine_name",
            "rule",
            "rule_name",
            "title",
            "message",
            "severity",
            "source_ip",
            "first_seen",
            "last_seen",
            "occurrence_count",
            "deduplication_key",
            "metadata",
            "created_at",
            "updated_at",
        ]


class AlertStatusUpdateSerializer(serializers.ModelSerializer):
    """
    Minimal serializer used to update the status of an alert (e.g. resolve/ack).
    """

    class Meta:
        model = Alert
        fields = ["status"]

    def validate_status(self, value):
        if value not in AlertStatus.values:
            raise serializers.ValidationError("Invalid status value.")
        return value
