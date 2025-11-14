from __future__ import annotations

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from alerts.models import Alert
from core.models import SeverityLevel
from machines.auth import issue_machine_jwt
from machines.models import Machine
from rules.models import Rule


@pytest.mark.django_db
def test_ingestion_triggers_ssh_bruteforce_alert(api_client):
    """
    Full integration test:

    - Create a machine
    - Create a rule for ssh_failed_login (threshold=3 in 5 minutes)
    - Issue a machine JWT
    - Ingest 3 ssh_failed_login events from the same IP
    - Verify that an Alert is created/updated
    """

    # 1) Create machine directly in DB
    machine = Machine.objects.create(
        name="test-machine-ssh",
        hostname="test-machine-ssh.local",
        ip_address="10.0.0.10",
    )

    # 2) Create SSH brute-force rule
    rule = Rule.objects.create(
        name="SSH Brute Force Attempt Detected",
        slug="ssh-brute-force",
        description=(
            "Detects multiple failed SSH login attempts from the same source IP "
            "within a short time interval, indicating a possible brute-force attack."
        ),
        enabled=True,
        event_type="ssh_failed_login",
        severity=SeverityLevel.HIGH,
        threshold=3,
        window_minutes=5,
    )

    # 3) Issue machine JWT
    access_token, _ = issue_machine_jwt(machine)

    # 4) Ingest 3 ssh_failed_login events in the time window
    url_ingest = reverse("log-ingest")
    base_time = timezone.now()

    common_payload = {
        "event_type": "ssh_failed_login",
        "source_ip": "10.0.0.5",
        "username": "admin",
    }

    # Helper to post a log with different timestamps
    def post_log(delta_minutes: int, port: int):
        payload = {
            **common_payload,
            "timestamp": (base_time + timedelta(minutes=delta_minutes)).isoformat(),
            "raw_message": (
                f"Failed password for invalid user admin from 10.0.0.5 port {port} ssh2"
            ),
        }
        return api_client.post(
            url_ingest,
            payload,
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {access_token}",
        )

    resp1 = post_log(0, 4444)
    resp2 = post_log(1, 4445)
    resp3 = post_log(2, 4446)

    assert resp1.status_code == 201
    assert resp2.status_code == 201
    assert resp3.status_code == 201

    # 5) Verify that an Alert was created
    alerts = Alert.objects.filter(
        machine=machine,
        rule=rule,
        source_ip="10.0.0.5",
    )
    assert alerts.exists(), "Expected at least one alert for SSH brute force."

    alert = alerts.first()
    assert alert.occurrence_count >= 3
    assert alert.severity == SeverityLevel.HIGH
    assert "SSH Brute Force" in alert.title or "SSH Brute" in alert.title
