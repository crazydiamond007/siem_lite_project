# alerts/admin.py
import json

from django.contrib import admin

from .models import Alert


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    """
    Admin configuration for the Alert model.

    This version matches the new Alert model:
    - Uses `occurrences` (not `occurrence_count`)
    - No `deduplication_key` field
    - Exposes `source_ip` via metadata helper
    """

    list_display = (
        "id",
        "title",
        "machine",
        "severity",
        "status",
        "occurrences",
        "source_ip",
        "first_seen",
        "last_seen",
    )

    list_filter = (
        "severity",
        "status",
        "rule",
        "machine",
        "is_escalated",
    )

    search_fields = (
        "title",
        "description",
        "rule__name",
        "machine__hostname",
    )

    readonly_fields = (
        "first_seen",
        "last_seen",
        "occurrences",
        "created_at",
        "updated_at",
        "metadata_pretty",
    )

    fieldsets = (
        (
            None,
            {
                "fields": (
                    "rule",
                    "machine",
                    "title",
                    "description",
                    "severity",
                    "status",
                    "occurrences",
                    "is_escalated",
                )
            },
        ),
        (
            "Timeline",
            {
                "fields": (
                    "first_seen",
                    "last_seen",
                    "created_at",
                    "updated_at",
                )
            },
        ),
        (
            "Metadata",
            {
                "fields": ("metadata_pretty",),
            },
        ),
    )

    def source_ip(self, obj):
        """
        Convenience column to show the source IP if present in metadata.
        """
        if not obj.metadata:
            return ""
        return obj.metadata.get("source_ip", "")

    source_ip.short_description = "Source IP"

    def metadata_pretty(self, obj):
        """
        Read-only formatted JSON for the metadata field.
        """
        if not obj.metadata:
            return "{}"
        try:
            return json.dumps(
                obj.metadata, indent=2, sort_keys=True, ensure_ascii=False
            )
        except Exception:
            # Fallback if metadata is not JSON-serializable for some reason
            return str(obj.metadata)

    metadata_pretty.short_description = "Metadata"
