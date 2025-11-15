# alerts/models.py
from django.db import models
from django.utils import timezone


class Alert(models.Model):
    """
    A security alert raised by the rule engine.

    Alerts are deduplicated: multiple events that match the same rule + machine
    will increment `occurrences` (and `occurrence_count`) and update `last_seen`
    instead of creating infinite rows.
    """

    SEVERITY_LOW = "low"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_HIGH = "high"
    SEVERITY_CRITICAL = "critical"

    SEVERITY_CHOICES = [
        (SEVERITY_LOW, "Low"),
        (SEVERITY_MEDIUM, "Medium"),
        (SEVERITY_HIGH, "High"),
        (SEVERITY_CRITICAL, "Critical"),
    ]

    STATUS_OPEN = "open"
    STATUS_ACK = "ack"
    STATUS_CLOSED = "closed"

    STATUS_CHOICES = [
        (STATUS_OPEN, "Open"),
        (STATUS_ACK, "Acknowledged"),
        (STATUS_CLOSED, "Closed"),
    ]

    rule = models.ForeignKey(
        "rules.Rule",
        on_delete=models.CASCADE,
        related_name="alerts",
    )
    machine = models.ForeignKey(
        "machines.Machine",
        on_delete=models.CASCADE,
        related_name="alerts",
    )

    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)

    severity = models.CharField(
        max_length=16,
        choices=SEVERITY_CHOICES,
        default=SEVERITY_LOW,
    )

    status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default=STATUS_OPEN,
    )

    # New: explicit source IP field (tests filter on this)
    source_ip = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text="Source IP address that triggered this alert (if applicable).",
    )

    # Internal + exposed counter.
    # Tests expect `occurrence_count` to be >= threshold.
    occurrences = models.PositiveIntegerField(default=1)
    occurrence_count = models.PositiveIntegerField(
        default=0,
        help_text="Mirror of occurrences, kept for backward compatibility and tests.",
    )

    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    is_escalated = models.BooleanField(default=False)

    # Arbitrary structured data about what triggered the alert
    # e.g. {"source_ip": "...", "username": "...", "port": 22}
    metadata = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-last_seen", "-severity", "-occurrence_count", "-occurrences"]

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.title} ({self.machine})"

    def mark_acknowledged(self) -> None:
        if self.status != self.STATUS_CLOSED:
            self.status = self.STATUS_ACK
            self.save(update_fields=["status", "updated_at"])

    def mark_closed(self) -> None:
        self.status = self.STATUS_CLOSED
        self.save(update_fields=["status", "updated_at"])

    def bump_occurrence(self) -> None:
        """
        Increment the occurrences counter and keep occurrence_count in sync.
        """
        current = self.occurrences or 0
        current += 1
        self.occurrences = current
        self.occurrence_count = current
        self.last_seen = timezone.now()
        self.save(
            update_fields=[
                "occurrences",
                "occurrence_count",
                "last_seen",
                "updated_at",
            ]
        )
