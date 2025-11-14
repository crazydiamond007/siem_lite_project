from __future__ import annotations

import pytest
from rest_framework.test import APIClient


@pytest.fixture
def api_client() -> APIClient:
    """
    DRF API client for integration tests.
    """
    return APIClient()
