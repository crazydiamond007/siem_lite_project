# Register your models here.
from django.contrib import admin

from .models import Machine


@admin.register(Machine)
class MachineAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "hostname",
        "ip_address",
        "is_active",
        "last_heartbeat",
        "registered_at",
        "created_at",
    )
    list_filter = ("is_active", "created_at", "last_heartbeat")
    search_fields = ("name", "hostname", "ip_address", "api_token")
    readonly_fields = (
        "api_token",
        "registered_at",
        "created_at",
        "updated_at",
    )
    ordering = ("-created_at",)
