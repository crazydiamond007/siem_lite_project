# Register your models here.
from django.contrib import admin

from .models import LogEntry


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = (
        "timestamp",
        "machine",
        "event_type",
        "severity",
        "source_ip",
        "username",
    )
    list_filter = (
        "event_type",
        "severity",
        "machine",
        "source_ip",
        "username",
        "timestamp",
    )
    search_fields = (
        "raw_message",
        "event_type",
        "machine__name",
        "source_ip",
        "username",
    )
    readonly_fields = (
        "created_at",
        "updated_at",
        "ingested_at",
    )
    date_hierarchy = "timestamp"
    ordering = ("-timestamp",)
