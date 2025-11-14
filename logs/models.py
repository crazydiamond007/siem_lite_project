# Create your models here.
from __future__ import annotations

from django.db import models

from core.models import TimeStampedModel, SeverityLevel
from machines.models import Machine


class LogEntry(TimeStampedModel):
    """
    Normalized log entry as ingested from agents.

    Raw log lines are normalized into a structured representation but we also
    keep the full raw message for forensics.
    """

    machine = models.ForeignKey(
        Machine,
        on_delete=models.CASCADE,
        related_name="logs",
        help_text="Machine that produced this log entry.",
    )

    # When the event occurred on the source machine (agent timestamp)
    timestamp = models.DateTimeField(
        db_index=True,
        help_text="Timestamp when the event occurred on the source machine.",
    )

    # When SIEM-Lite ingested the event
    ingested_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="Timestamp when this log entry was ingested by SIEM-Lite.",
    )

    event_type = models.CharField(
        max_length=64,
        db_index=True,
        help_text="Normalized event type (e.g. 'ssh_failed_login', 'sudo_command').",
    )

    severity = models.CharField(
        max_length=16,
        choices=SeverityLevel.choices,
        default=SeverityLevel.INFO,
        db_index=True,
        help_text="Optional severity level assigned during ingestion.",
    )

    raw_message = models.TextField(
        help_text="Original raw log line or message.",
    )

    source_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        db_index=True,
        help_text="Source IP address if available (for network/SSH events).",
    )

    username = models.CharField(
        max_length=150,
        blank=True,
        db_index=True,
        help_text="Username if applicable to this log entry.",
    )

    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Additional normalized fields (port, process, path, etc.).",
    )

    correlation_id = models.CharField(
        max_length=64,
        blank=True,
        db_index=True,
        help_text="Optional correlation key to group related logs together.",
    )

    class Meta:
        db_table = "logs_logentry"
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["event_type", "timestamp"]),
            models.Index(fields=["machine", "timestamp"]),
        ]
        verbose_name = "Log entry"
        verbose_name_plural = "Log entries"

    def __str__(self) -> str:
        return f"[{self.event_type}] {self.machine} @ {self.timestamp.isoformat()}"
