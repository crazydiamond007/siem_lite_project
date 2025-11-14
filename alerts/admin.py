# Register your models here.
from django.contrib import admin

from .models import Alert


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = (
        "title",
        "machine",
        "rule",
        "severity",
        "status",
        "source_ip",
        "occurrence_count",
        "first_seen",
        "last_seen",
    )
    list_filter = (
        "severity",
        "status",
        "machine",
        "rule",
        "source_ip",
        "first_seen",
        "last_seen",
    )
    search_fields = (
        "title",
        "message",
        "machine__name",
        "rule__name",
        "source_ip",
        "deduplication_key",
    )
    readonly_fields = (
        "created_at",
        "updated_at",
        "first_seen",
        "last_seen",
        "occurrence_count",
        "deduplication_key",
    )
    date_hierarchy = "first_seen"
    ordering = ("-first_seen",)
