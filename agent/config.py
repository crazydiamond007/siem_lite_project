from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict


# Where we persist machine_id + api_token locally
DEFAULT_STATE_FILE = Path.home() / ".siem_lite_agent.json"


@dataclass
class AgentConfig:
    base_url: str
    machine_name: str
    hostname: str
    ip_address: str | None
    state_file: Path = DEFAULT_STATE_FILE

    @property
    def register_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/api/machines/register/"

    @property
    def machine_token_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/api/machines/token/"

    @property
    def log_ingest_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/api/logs/ingest/"


@dataclass
class AgentState:
    machine_id: str
    api_token: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "machine_id": self.machine_id,
            "api_token": self.api_token,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "AgentState":
        return AgentState(
            machine_id=data["machine_id"],
            api_token=data["api_token"],
        )


def load_config() -> AgentConfig:
    """
    Build AgentConfig from environment variables and local environment.
    """

    base_url = os.getenv("SIEM_BASE_URL", "http://127.0.0.1:8000")
    machine_name = os.getenv("SIEM_MACHINE_NAME", socket.gethostname())
    hostname = socket.gethostname()
    ip_address = os.getenv("SIEM_MACHINE_IP") or None

    return AgentConfig(
        base_url=base_url,
        machine_name=machine_name,
        hostname=hostname,
        ip_address=ip_address,
    )


def load_state(config: AgentConfig) -> AgentState | None:
    """
    Load machine_id + api_token from local state file, if present.
    """
    if not config.state_file.exists():
        return None

    try:
        data = json.loads(config.state_file.read_text(encoding="utf-8"))
        return AgentState.from_dict(data)
    except Exception:
        # If state is corrupted, treat as missing
        return None


def save_state(config: AgentConfig, state: AgentState) -> None:
    """
    Persist machine_id + api_token to local state file with restricted permissions.
    """
    config.state_file.write_text(
        json.dumps(state.to_dict(), indent=2), encoding="utf-8"
    )
    # Best-effort permission tightening on Unix-like systems
    try:
        os.chmod(config.state_file, 0o600)
    except PermissionError:
        # Ignore if we cannot change permissions
        pass
