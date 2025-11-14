# Register your models here.
from django.contrib import admin

from .models import Rule


@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "slug",
        "event_type",
        "severity",
        "threshold",
        "window_minutes",
        "enabled",
        "created_at",
    )
    list_filter = ("enabled", "severity", "event_type", "created_at")
    search_fields = ("name", "slug", "description", "event_type")
    prepopulated_fields = {"slug": ("name",)}
    readonly_fields = ("created_at", "updated_at")
    ordering = ("name",)
