from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Tuple

import jwt
from django.conf import settings

from .models import Machine


class MachineTokenError(Exception):
    """Base error for machine token problems."""


class MachineTokenInvalid(MachineTokenError):
    """Raised when a token is invalid or not a machine token."""


class MachineTokenExpired(MachineTokenError):
    """Raised when a machine token has expired."""


def issue_machine_jwt(
    machine: Machine, expires_in_minutes: int = 30
) -> Tuple[str, int]:
    """
    Issue a short-lived JWT for a machine.

    Payload contains:
      - sub: machine UUID
      - type: 'machine'
      - iat: issued-at timestamp
      - exp: expiration

    Returns (token, expires_in_seconds).
    """
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=expires_in_minutes)

    payload = {
        "sub": str(machine.id),
        "type": "machine",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    expires_in_seconds = int((exp - now).total_seconds())
    return token, expires_in_seconds


def authenticate_machine_from_jwt(token: str) -> Machine:
    """
    Validate a machine JWT and return the corresponding Machine instance.

    Raises MachineTokenInvalid / MachineTokenExpired on error.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=["HS256"],
        )
    except jwt.ExpiredSignatureError as exc:
        raise MachineTokenExpired("Machine token has expired.") from exc
    except jwt.PyJWTError as exc:
        raise MachineTokenInvalid("Invalid machine token.") from exc

    if payload.get("type") != "machine":
        raise MachineTokenInvalid("Token is not a machine token.")

    machine_id = payload.get("sub")
    if not machine_id:
        raise MachineTokenInvalid("Token is missing 'sub' claim for machine ID.")

    try:
        machine = Machine.objects.get(pk=machine_id, is_active=True)
    except Machine.DoesNotExist as exc:
        raise MachineTokenInvalid("Machine not found or inactive.") from exc

    return machine
