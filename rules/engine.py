from __future__ import annotations

from datetime import timedelta
from typing import Iterable


from .models import Rule
from alerts.engine import create_or_update_alert
from logs.models import LogEntry


def apply_rules_to_log_entry(log_entry: LogEntry) -> None:
    """
    Evaluate all enabled rules that match this log entry's event_type.

    For now this is a very simple implementation:
    - Filter rules by event_type and enabled=True
    - For each rule, count matching events in the sliding window
    - If threshold exceeded, raise or update an Alert
    """

    matching_rules: Iterable[Rule] = Rule.objects.filter(
        enabled=True, event_type=log_entry.event_type
    )

    for rule in matching_rules:
        _evaluate_rule_on_log_entry(rule, log_entry)


def _evaluate_rule_on_log_entry(rule: Rule, log_entry: LogEntry) -> None:
    """
    Simple windowed count rule:

    Example: "ssh_failed_login", threshold=5, window_minutes=3
    → if there are >= 5 such events from the same source IP in last 3 minutes,
      create/update an alert.
    """
    window_end = log_entry.timestamp
    window_start = window_end - timedelta(minutes=rule.window_minutes)

    qs = LogEntry.objects.filter(
        machine=log_entry.machine,
        event_type=rule.event_type,
        timestamp__gte=window_start,
        timestamp__lte=window_end,
    )

    # Optionally refine per source_ip if available
    if log_entry.source_ip:
        qs = qs.filter(source_ip=log_entry.source_ip)

    count = qs.count()

    if count >= rule.threshold:
        create_or_update_alert(rule=rule, log_entry=log_entry, occurrences=count)
