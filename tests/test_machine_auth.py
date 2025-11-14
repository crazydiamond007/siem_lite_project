from __future__ import annotations

import pytest
from django.urls import reverse

from machines.models import Machine


@pytest.mark.django_db
def test_machine_registration_and_token(api_client):
    # 1) Register machine
    url_register = reverse("machine-register")
    payload = {
        "name": "test-machine-01",
        "hostname": "test-machine-01.local",
        "ip_address": "192.168.1.50",
    }

    resp = api_client.post(url_register, payload, format="json")
    assert resp.status_code == 201

    data = resp.json()
    assert "id" in data
    assert "api_token" in data
    api_token = data["api_token"]

    # Ensure machine exists in DB
    machine = Machine.objects.get(id=data["id"])
    assert machine.api_token == api_token
    assert machine.is_active is True

    # 2) Exchange api_token for machine JWT
    url_token = reverse("machine-token")
    resp2 = api_client.post(url_token, {"api_token": api_token}, format="json")
    assert resp2.status_code == 200

    data2 = resp2.json()
    assert data2["token_type"] == "machine"
    assert "access" in data2
    assert "machine_id" in data2
    assert data2["machine_id"] == str(machine.id)
    assert data2["expires_in"] > 0
