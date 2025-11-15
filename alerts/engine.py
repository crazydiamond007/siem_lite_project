# alerts/engine.py
import logging
from typing import Any, Dict, Optional

import requests
from django.conf import settings
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone

from .models import Alert
from rules.models import Rule
from machines.models import Machine

logger = logging.getLogger(__name__)


def _get_escalation_threshold() -> int:
    """
    Global threshold for auto-escalation when occurrences keep increasing.
    Can be overridden via settings.ALERT_ESCALATION_THRESHOLD.
    """
    return getattr(settings, "ALERT_ESCALATION_THRESHOLD", 10)


def _should_escalate(alert: Alert) -> bool:
    """
    Decide if an alert should be escalated.

    Current policy:
    - Critical severity => escalate immediately.
    - High severity with occurrences >= threshold => escalate.
    - Any severity with occurrences >= 2 * threshold => escalate as noisy.
    """
    if alert.is_escalated:
        return False

    threshold = _get_escalation_threshold()

    if alert.severity == Alert.SEVERITY_CRITICAL:
        return True

    if alert.severity == Alert.SEVERITY_HIGH and alert.occurrences >= threshold:
        return True

    if alert.occurrences >= 2 * threshold:
        return True

    return False


def _format_alert_message(alert: Alert) -> str:
    """
    Human-readable notification message used for email/Telegram.
    """
    machine_name = str(alert.machine)
    rule_name = str(alert.rule)

    lines = [
        f"SIEM-Lite Alert: {alert.title}",
        "",
        f"Rule: {rule_name}",
        f"Machine: {machine_name}",
        f"Severity: {alert.severity.upper()}",
        f"Status: {alert.status}",
        f"Occurrences: {alert.occurrences}",
        f"First seen: {alert.first_seen.isoformat()}",
        f"Last seen: {alert.last_seen.isoformat()}",
    ]

    if alert.source_ip:
        lines.append(f"Source IP: {alert.source_ip}")

    if alert.description:
        lines.append("")
        lines.append("Description:")
        lines.append(alert.description)

    if alert.metadata:
        lines.append("")
        lines.append("Metadata:")
        for key, value in alert.metadata.items():
            lines.append(f"- {key}: {value}")

    return "\n".join(lines)


def _notify_via_email(alert: Alert) -> None:
    """
    Send alert via email if settings are configured.

    Required settings:
    - ALERT_EMAIL_RECIPIENTS: list of recipient emails
    - DEFAULT_FROM_EMAIL or SERVER_EMAIL
    """
    recipients = getattr(settings, "ALERT_EMAIL_RECIPIENTS", None)
    if not recipients:
        logger.debug(
            "Skipping email alert notification: ALERT_EMAIL_RECIPIENTS not set"
        )
        return

    subject = f"[SIEM-Lite] {alert.severity.upper()} alert on {alert.machine}"
    message = _format_alert_message(alert)
    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", None) or getattr(
        settings, "SERVER_EMAIL", None
    )

    if not from_email:
        logger.warning(
            "Cannot send email alert: DEFAULT_FROM_EMAIL / SERVER_EMAIL not configured"
        )
        return

    try:
        send_mail(subject, message, from_email, recipients, fail_silently=False)
        logger.info("Sent email alert notification for alert %s", alert.id)
    except Exception as exc:
        logger.exception("Failed to send email alert notification: %s", exc)


def _notify_via_telegram(alert: Alert) -> None:
    """
    Send alert via Telegram if settings are configured.

    Required settings:
    - TELEGRAM_BOT_TOKEN
    - TELEGRAM_CHAT_ID
    """
    bot_token = getattr(settings, "TELEGRAM_BOT_TOKEN", None)
    chat_id = getattr(settings, "TELEGRAM_CHAT_ID", None)

    if not bot_token or not chat_id:
        logger.debug(
            "Skipping Telegram alert notification: TELEGRAM_BOT_TOKEN/CHAT_ID not set"
        )
        return

    text = _format_alert_message(alert)
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    try:
        resp = requests.post(
            url,
            json={"chat_id": chat_id, "text": text},
            timeout=5,
        )
        if resp.status_code != 200:
            logger.warning(
                "Telegram notification failed (%s): %s",
                resp.status_code,
                resp.text,
            )
        else:
            logger.info("Sent Telegram alert notification for alert %s", alert.id)
    except Exception as exc:
        logger.exception("Failed to send Telegram alert notification: %s", exc)


def _send_notifications(alert: Alert) -> None:
    """
    Send notifications (email, Telegram, etc.) for a given alert.
    Called when an alert is created or escalated.
    """
    _notify_via_email(alert)
    _notify_via_telegram(alert)


def _extract_metadata_from_log_entry(log_entry: Any) -> Dict[str, Any]:
    """
    Build a metadata dict from a LogEntry instance.

    We are defensive here because we don't want tight coupling to the LogEntry model
    structure. We just grab common attributes if they exist.
    """
    meta: Dict[str, Any] = {}

    # Common top-level attributes we care about
    for attr in [
        "event_type",
        "source_ip",
        "username",
        "raw_message",
        "process",
        "pid",
    ]:
        value = getattr(log_entry, attr, None)
        if value is not None:
            meta[attr] = value

    # If the log entry has a JSON or dict-like metadata/extra field, merge it
    for attr in ["metadata", "extra", "payload"]:
        extra = getattr(log_entry, attr, None)
        if isinstance(extra, dict):
            # Log metadata wins; do not overwrite existing keys
            for k, v in extra.items():
                meta.setdefault(k, v)

    return meta


@transaction.atomic
def create_or_update_alert(
    *,
    rule: Rule,
    machine: Optional[Machine] = None,
    log_entry: Optional[Any] = None,
    severity: Optional[str] = None,
    title: Optional[str] = None,
    description: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    occurrences: Optional[int] = None,
) -> Alert:
    """
    Main entry point used by the rule engine whenever a rule fires.

    The rules.engine currently calls:

        create_or_update_alert(rule=rule, log_entry=log_entry, occurrences=count)

    Behaviour:
    - If log_entry is provided, we extract:
        * machine from log_entry.machine
        * source_ip from log_entry.source_ip (if present)
        * metadata from log_entry (source_ip, username, raw_message, ...)
      unless these are explicitly passed.
    - Find an existing OPEN alert for the same (rule, machine, source_ip).
    - If found: update occurrences (to `occurrences` if given, otherwise +1),
      update last_seen, merge metadata, possibly bump severity.
    - Else: create a new alert row, with occurrences = `occurrences` or 1.
    - Keep `occurrence_count` in sync with `occurrences`.
    - If escalation conditions are met, mark as escalated and send notifications.
    - On first creation, also send notifications.

    Returns the Alert instance (fresh from DB).
    """

    # Derive machine, metadata and source_ip from log_entry if needed
    if log_entry is not None:
        if machine is None:
            machine = getattr(log_entry, "machine", None)

        if metadata is None:
            metadata = _extract_metadata_from_log_entry(log_entry)

        if description is None:
            raw_msg = getattr(log_entry, "raw_message", None)
            if raw_msg:
                description = raw_msg

    if machine is None:
        raise ValueError(
            "create_or_update_alert requires a machine or a log_entry with machine"
        )

    metadata = metadata or {}

    # Determine source_ip (explicit field on Alert)
    source_ip = getattr(log_entry, "source_ip", None) if log_entry is not None else None
    if source_ip is None:
        source_ip = metadata.get("source_ip")

    effective_severity = severity or getattr(rule, "severity", Alert.SEVERITY_LOW)

    # Try to find an existing open alert for this rule+machine+source_ip
    filter_kwargs = {
        "rule": rule,
        "machine": machine,
        "status": Alert.STATUS_OPEN,
    }
    if source_ip:
        filter_kwargs["source_ip"] = source_ip

    existing = (
        Alert.objects.select_for_update()
        .filter(**filter_kwargs)
        .order_by("-last_seen")
        .first()
    )

    if existing:
        # Update existing alert (deduplication)
        if occurrences is not None:
            current = occurrences
        else:
            current = (existing.occurrences or 0) + 1

        existing.occurrences = current
        existing.occurrence_count = current
        existing.last_seen = timezone.now()

        # Ensure source_ip is set if we have it now
        if source_ip and not existing.source_ip:
            existing.source_ip = source_ip

        # Merge metadata (existing values win, only add new keys)
        if existing.metadata is None:
            existing.metadata = metadata
        else:
            merged = dict(existing.metadata)
            for k, v in metadata.items():
                merged.setdefault(k, v)
            existing.metadata = merged

        # Optionally, severity might be bumped up (never down)
        severity_order = [
            Alert.SEVERITY_LOW,
            Alert.SEVERITY_MEDIUM,
            Alert.SEVERITY_HIGH,
            Alert.SEVERITY_CRITICAL,
        ]
        current_index = severity_order.index(existing.severity)
        new_index = severity_order.index(effective_severity)
        if new_index > current_index:
            existing.severity = effective_severity

        existing.save()

        if _should_escalate(existing):
            existing.is_escalated = True
            existing.save(update_fields=["is_escalated", "updated_at"])
            _send_notifications(existing)

        return existing

    # No open alert => create a brand new one
    if title is None:
        hostname = getattr(machine, "hostname", str(machine))
        title = f"Rule '{rule.name}' triggered on {hostname}"

    if description is None:
        description = getattr(rule, "description", "") or ""

    current = occurrences if occurrences is not None else 1

    alert = Alert.objects.create(
        rule=rule,
        machine=machine,
        title=title,
        description=description,
        severity=effective_severity,
        status=Alert.STATUS_OPEN,
        source_ip=source_ip,
        occurrences=current,
        occurrence_count=current,
        first_seen=timezone.now(),
        last_seen=timezone.now(),
        is_escalated=False,
        metadata=metadata,
    )

    # First time we see this alert => notify immediately
    _send_notifications(alert)

    return alert
