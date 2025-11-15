# Create your views here.
from __future__ import annotations

from datetime import timedelta

from django.utils import timezone
from django.views.generic import TemplateView

from alerts.models import Alert
from logs.models import LogEntry
from machines.models import Machine


class DashboardView(TemplateView):
    """
    Simple SIEM-Lite dashboard.

    Shows:
      - high-level counters
      - recent alerts
      - recent log entries
    """

    template_name = "dashboard/index.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)

        now = timezone.now()
        last_24h = now - timedelta(hours=24)

        ctx["now"] = now
        ctx["last_24h"] = last_24h

        # High-level metrics
        ctx["machines_count"] = Machine.objects.count()
        ctx["alerts_open_count"] = Alert.objects.filter(status="open").count()
        ctx["alerts_high_open_count"] = Alert.objects.filter(
            status="open", severity="high"
        ).count()
        ctx["alerts_last_24h"] = Alert.objects.filter(last_seen__gte=last_24h).count()

        # Recent alerts
        ctx["recent_alerts"] = Alert.objects.select_related("machine").order_by(
            "-last_seen"
        )[:10]

        # Recent logs
        ctx["recent_logs"] = LogEntry.objects.select_related("machine").order_by(
            "-timestamp"
        )[:10]

        return ctx
