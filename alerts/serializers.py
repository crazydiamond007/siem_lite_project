from rest_framework import serializers

from .models import Alert


class AlertSerializer(serializers.ModelSerializer):
    rule_name = serializers.CharField(source="rule.name", read_only=True)
    machine_name = serializers.CharField(source="machine.hostname", read_only=True)

    class Meta:
        model = Alert
        fields = [
            "id",
            "rule",
            "rule_name",
            "machine",
            "machine_name",
            "title",
            "description",
            "severity",
            "status",
            "source_ip",
            "occurrences",
            "occurrence_count",
            "first_seen",
            "last_seen",
            "is_escalated",
            "metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "rule",
            "machine",
            "rule_name",
            "machine_name",
            "first_seen",
            "last_seen",
            "occurrences",
            "occurrence_count",
            "is_escalated",
            "created_at",
            "updated_at",
        ]
