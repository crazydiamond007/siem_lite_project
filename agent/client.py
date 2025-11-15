from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Tuple

import httpx

from .config import AgentConfig, AgentState, load_state, save_state


class AgentError(Exception):
    """Base class for agent-related errors."""


class RegistrationError(AgentError):
    """Raised when machine registration fails."""


class TokenError(AgentError):
    """Raised when machine JWT retrieval fails."""


class IngestionError(AgentError):
    """Raised when log ingestion fails."""


def _new_http_client() -> httpx.Client:
    """
    Create a simple synchronous HTTP client.

    For now we keep it basic; we can later add retries, timeouts, proxies, etc.
    """
    return httpx.Client(timeout=10.0)


def ensure_registered(config: AgentConfig) -> AgentState:
    """
    Ensure the agent is registered with the SIEM backend.

    If we have a local state file, reuse it.
    Otherwise, call /api/machines/register/ and persist the returned credentials.
    """
    state = load_state(config)
    if state is not None:
        return state

    payload: Dict[str, Any] = {
        "name": config.machine_name,
        "hostname": config.hostname,
    }
    if config.ip_address:
        payload["ip_address"] = config.ip_address

    with _new_http_client() as client:
        resp = client.post(config.register_url, json=payload)
        if resp.status_code != 201:
            raise RegistrationError(
                f"Machine registration failed ({resp.status_code}): {resp.text}"
            )

        data = resp.json()
        state = AgentState(
            machine_id=data["id"],
            api_token=data["api_token"],
        )
        save_state(config, state)
        return state


def get_machine_jwt(config: AgentConfig, state: AgentState) -> Tuple[str, int]:
    """
    Exchange api_token + machine_id for a short-lived machine JWT.
    """
    payload = {
        "api_token": state.api_token,
        "machine_id": state.machine_id,
    }

    with _new_http_client() as client:
        resp = client.post(config.machine_token_url, json=payload)
        if resp.status_code != 200:
            raise TokenError(
                f"Failed to obtain machine JWT ({resp.status_code}): {resp.text}"
            )

        data = resp.json()
        return data["access"], int(data["expires_in"])


def send_log_event(
    config: AgentConfig,
    machine_jwt: str,
    *,
    timestamp: datetime,
    event_type: str,
    raw_message: str,
    source_ip: str | None = None,
    username: str | None = None,
    severity: str | None = None,
    metadata: Dict[str, Any] | None = None,
) -> str:
    """
    Send a single normalized log event to the SIEM backend.

    Returns the log entry ID on success.
    """
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    payload: Dict[str, Any] = {
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "raw_message": raw_message,
    }

    if source_ip:
        payload["source_ip"] = source_ip
    if username:
        payload["username"] = username
    if severity:
        payload["severity"] = severity
    if metadata is not None:
        payload["metadata"] = metadata

    headers = {
        "Authorization": f"Bearer {machine_jwt}",
    }

    with _new_http_client() as client:
        resp = client.post(config.log_ingest_url, json=payload, headers=headers)
        if resp.status_code != 201:
            raise IngestionError(
                f"Log ingestion failed ({resp.status_code}): {resp.text}"
            )

        data = resp.json()
        return data["id"]
