from __future__ import annotations


from .models import Alert, AlertStatus
from core.models import SeverityLevel
from logs.models import LogEntry
from rules.models import Rule


def _build_dedup_key(rule: Rule, log_entry: LogEntry) -> str:
    """
    Build a deterministic deduplication key used to group alerts.
    """
    parts = [
        str(log_entry.machine_id),
        str(rule.id),
        log_entry.source_ip or "",
    ]
    return "|".join(parts)


def create_or_update_alert(
    *, rule: Rule, log_entry: LogEntry, occurrences: int = 1
) -> Alert:
    """
    Create a new alert or update an existing one if a matching
    deduplication key is found.

    For now, we consider alerts with same (machine, rule, source_ip)
    as duplicates until resolved.
    """
    dedup_key = _build_dedup_key(rule, log_entry)

    alert, created = Alert.objects.get_or_create(
        deduplication_key=dedup_key,
        defaults={
            "machine": log_entry.machine,
            "rule": rule,
            "title": f"{rule.name} on {log_entry.machine.name}",
            "message": _build_alert_message(rule, log_entry, occurrences),
            "severity": rule.severity or SeverityLevel.MEDIUM,
            "status": AlertStatus.OPEN,
            "source_ip": log_entry.source_ip,
            "first_seen": log_entry.timestamp,
            "last_seen": log_entry.timestamp,
            "occurrence_count": occurrences,
            "metadata": {
                "event_type": log_entry.event_type,
                "recent_log_id": str(log_entry.id),
            },
        },
    )

    if not created:
        alert.last_seen = log_entry.timestamp
        alert.occurrence_count = max(alert.occurrence_count, occurrences)
        alert.message = _build_alert_message(rule, log_entry, alert.occurrence_count)
        alert.status = AlertStatus.OPEN  # re-open if it was suppressed/ack
        alert.save(
            update_fields=[
                "last_seen",
                "occurrence_count",
                "message",
                "status",
                "updated_at",
            ]
        )

    return alert


def _build_alert_message(rule: Rule, log_entry: LogEntry, occurrences: int) -> str:
    base = f"Rule '{rule.name}' triggered on machine '{log_entry.machine.name}'."
    details = (
        f" Event type: {log_entry.event_type}. Occurrences in window: {occurrences}."
    )
    if log_entry.source_ip:
        details += f" Source IP: {log_entry.source_ip}."
    return base + details
