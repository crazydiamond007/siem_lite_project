from __future__ import annotations

from rest_framework import serializers

from .models import Rule


class RuleSerializer(serializers.ModelSerializer):
    """
    Full Rule representation for admin-oriented CRUD.
    """

    class Meta:
        model = Rule
        fields = [
            "id",
            "name",
            "slug",
            "description",
            "enabled",
            "event_type",
            "severity",
            "threshold",
            "window_minutes",
            "parameters",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]
