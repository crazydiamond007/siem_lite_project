# Create your models here.
from __future__ import annotations

from django.db import models

from core.models import TimeStampedModel, SeverityLevel


class Rule(TimeStampedModel):
    """
    Detection rule applied on normalized log entries.

    Typical examples:
    - SSH brute-force: N failed logins from same IP within M minutes
    - Port scan: connections to many ports from same source within window
    """

    name = models.CharField(
        max_length=150,
        unique=True,
        help_text="Human-readable name of the rule.",
    )
    slug = models.SlugField(
        max_length=150,
        unique=True,
        help_text="Stable slug identifier for programmatic reference.",
    )

    description = models.TextField(
        blank=True,
        help_text="Optional description of what this rule detects.",
    )

    enabled = models.BooleanField(
        default=True,
        help_text="Disabled rules are ignored by the rule engine.",
    )

    event_type = models.CharField(
        max_length=64,
        db_index=True,
        help_text="Normalized event_type that this rule applies to (e.g. 'ssh_failed_login').",
    )

    severity = models.CharField(
        max_length=16,
        choices=SeverityLevel.choices,
        default=SeverityLevel.MEDIUM,
        help_text="Default severity level for alerts produced by this rule.",
    )

    threshold = models.PositiveIntegerField(
        default=5,
        help_text="Minimum number of matching events within the window to trigger an alert.",
    )

    window_minutes = models.PositiveIntegerField(
        default=5,
        help_text="Time window in minutes over which events are counted.",
    )

    # Optional: additional parameters for the engine (e.g. JSON condition tree)
    parameters = models.JSONField(
        default=dict,
        blank=True,
        help_text="Optional engine-specific parameters or conditions.",
    )

    class Meta:
        db_table = "rules_rule"
        ordering = ["name"]
        verbose_name = "Rule"
        verbose_name_plural = "Rules"

    def __str__(self) -> str:
        return self.name
