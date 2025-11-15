# alerts/models.py
from django.db import models
from django.utils import timezone


class Alert(models.Model):
    """
    A security alert raised by the rule engine.

    Alerts are deduplicated: multiple events that match the same rule + machine
    will increment `occurrences` and update `last_seen` instead of creating
    infinite rows.
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

    occurrences = models.PositiveIntegerField(default=1)

    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    is_escalated = models.BooleanField(default=False)

    # Arbitrary structured data about what triggered the alert
    # e.g. {"source_ip": "...", "username": "...", "port": 22}
    metadata = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-last_seen", "-severity", "-occurrences"]

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
        Increment the occurrences counter and update last_seen.
        """
        self.occurrences = models.F("occurrences") + 1
        # We use F() for atomic increment; refresh_instance_after_update in engine.
        self.last_seen = timezone.now()
        self.save(update_fields=["occurrences", "last_seen", "updated_at"])
