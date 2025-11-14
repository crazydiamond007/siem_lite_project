from __future__ import annotations

from rest_framework import serializers

from .models import LogEntry
from machines.models import Machine


class LogEntrySerializer(serializers.ModelSerializer):
    """
    Read-only representation of a log entry for admins / dashboards.
    """

    machine_name = serializers.CharField(source="machine.name", read_only=True)

    class Meta:
        model = LogEntry
        fields = [
            "id",
            "machine",
            "machine_name",
            "timestamp",
            "ingested_at",
            "event_type",
            "severity",
            "raw_message",
            "source_ip",
            "username",
            "metadata",
            "correlation_id",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class LogEntryIngestionSerializer(serializers.Serializer):
    """
    Payload used by agents to submit normalized log entries.

    Machine identity is resolved from the X-Machine-Token header,
    so it's not part of the JSON body.
    """

    timestamp = serializers.DateTimeField(
        help_text="When the event occurred on the source machine (ISO 8601)."
    )
    event_type = serializers.CharField(
        max_length=64,
        help_text="Normalized event type (e.g. 'ssh_failed_login').",
    )
    raw_message = serializers.CharField(
        help_text="Original raw log line or message.",
    )
    source_ip = serializers.IPAddressField(
        required=False,
        allow_null=True,
        help_text="Source IP address if available.",
    )
    username = serializers.CharField(
        max_length=150,
        required=False,
        allow_blank=True,
        help_text="Username if available.",
    )
    severity = serializers.ChoiceField(
        choices=LogEntry._meta.get_field("severity").choices,
        required=False,
        help_text="Optional severity; if omitted, defaults to INFO.",
    )
    metadata = serializers.DictField(
        child=serializers.CharField(allow_blank=True),
        required=False,
        help_text="Additional normalized fields (e.g. port, process, path).",
    )

    def create(self, validated_data):
        """
        Actual creation of LogEntry is handled in the view, because we need
        the Machine instance obtained from the authentication header.
        """
        raise NotImplementedError("Use the view to create LogEntry instances.")

    @staticmethod
    def create_entry(*, machine: Machine, validated_data: dict) -> LogEntry:
        """
        Helper method used by the view once it has both Machine + validated_data.
        """
        return LogEntry.objects.create(
            machine=machine,
            timestamp=validated_data["timestamp"],
            event_type=validated_data["event_type"],
            raw_message=validated_data["raw_message"],
            source_ip=validated_data.get("source_ip"),
            username=validated_data.get("username", ""),
            severity=validated_data.get("severity")
            or LogEntry._meta.get_field("severity").default,
            metadata=validated_data.get("metadata", {}),
        )
