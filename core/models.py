# Create your models here.
from __future__ import annotations

import uuid

from django.db import models
from django.utils.translation import gettext_lazy as _


class TimeStampedModel(models.Model):
    """
    Abstract base model that adds created_at / updated_at timestamps.
    """

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)

    class Meta:
        abstract = True


class SeverityLevel(models.TextChoices):
    """
    Common severity scale reused by Rules, Alerts, and (optionally) LogEntry.
    """

    INFO = "info", _("Info")
    LOW = "low", _("Low")
    MEDIUM = "medium", _("Medium")
    HIGH = "high", _("High")
    CRITICAL = "critical", _("Critical")


class UUIDPrimaryKeyModel(TimeStampedModel):
    """
    Abstract base model that uses a UUID as primary key.

    Useful for entities that are referenced from external systems (e.g. agents).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True
