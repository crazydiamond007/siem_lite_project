# Create your models here.
from __future__ import annotations

import secrets

from django.db import models

from core.models import UUIDPrimaryKeyModel


def generate_machine_token() -> str:
    # 32 bytes → 64 hex characters
    return secrets.token_hex(32)


class Machine(UUIDPrimaryKeyModel):
    """
    Represents a monitored machine / agent that sends logs to SIEM-Lite.
    """

    name = models.CharField(
        max_length=150,
        help_text="Human-friendly name of the machine (e.g. 'web-01', 'db-prod-1').",
    )
    hostname = models.CharField(
        max_length=255,
        blank=True,
        help_text="Optional hostname reported by the agent.",
    )
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="Last known IP address of the machine.",
    )
    description = models.TextField(
        blank=True,
        help_text="Optional description, environment, or notes.",
    )

    is_active = models.BooleanField(
        default=True,
        help_text="Inactive machines will not be allowed to send logs.",
    )

    # Token used by the agent to authenticate (typically embedded in JWT or used to mint JWT).
    api_token = models.CharField(
        max_length=128,
        unique=True,
        default=generate_machine_token,
        help_text="Secret token issued to the machine for API access.",
    )

    last_heartbeat = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last time the agent successfully contacted the server.",
    )
    registered_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp when the machine was initially registered.",
    )

    class Meta:
        db_table = "machines_machine"
        ordering = ["-created_at"]
        verbose_name = "Machine"
        verbose_name_plural = "Machines"

    def __str__(self) -> str:
        return self.name or str(self.id)
