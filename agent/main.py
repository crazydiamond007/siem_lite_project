from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

from .client import (
    AgentError,
    ensure_registered,
    get_machine_jwt,
    send_log_event,
)
from .config import load_config


def cmd_send_test_event() -> None:
    """
    Register the machine if needed, get a machine JWT,
    and send a single ssh_failed_login test event.
    """
    config = load_config()

    print(f"[agent] Using SIEM backend at: {config.base_url}")

    try:
        state = ensure_registered(config)
        print(f"[agent] Machine registered with id={state.machine_id}")
    except AgentError as exc:
        print(f"[agent] ERROR during registration: {exc}")
        return

    try:
        machine_jwt, expires_in = get_machine_jwt(config, state)
        print(f"[agent] Obtained machine JWT (expires in {expires_in} seconds).")
    except AgentError as exc:
        print(f"[agent] ERROR obtaining machine JWT: {exc}")
        return

    # Build a synthetic ssh_failed_login event
    now = datetime.now(timezone.utc)
    raw_message = "Failed password for invalid user admin from 10.0.0.5 port 4444 ssh2"

    try:
        log_id = send_log_event(
            config,
            machine_jwt,
            timestamp=now,
            event_type="ssh_failed_login",
            raw_message=raw_message,
            source_ip="10.0.0.5",
            username="admin",
            metadata={"port": "4444"},
        )
        print(f"[agent] Test event ingested successfully with id={log_id}")
    except AgentError as exc:
        print(f"[agent] ERROR sending log event: {exc}")


def cmd_send_burst(count: int, window_minutes: int) -> None:
    """
    Send a burst of ssh_failed_login events within a given time window
    to deliberately trigger the SSH brute-force rule.
    """
    config = load_config()
    print(f"[agent] Using SIEM backend at: {config.base_url}")
    print(f"[agent] Sending burst of {count} events over {window_minutes} minutes.")

    try:
        state = ensure_registered(config)
        print(f"[agent] Machine registered with id={state.machine_id}")
    except AgentError as exc:
        print(f"[agent] ERROR during registration: {exc}")
        return

    try:
        machine_jwt, expires_in = get_machine_jwt(config, state)
        print(f"[agent] Obtained machine JWT (expires in {expires_in} seconds).")
    except AgentError as exc:
        print(f"[agent] ERROR obtaining machine JWT: {exc}")
        return

    base_time = datetime.now(timezone.utc)
    if count <= 1:
        step = 0
    else:
        step = window_minutes / max(count - 1, 1)

    for i in range(count):
        minutes_offset = step * i
        event_time = base_time + timedelta(minutes=minutes_offset)
        port = 4444 + i

        raw_message = (
            f"Failed password for invalid user admin from 10.0.0.5 port {port} ssh2"
        )

        try:
            log_id = send_log_event(
                config,
                machine_jwt,
                timestamp=event_time,
                event_type="ssh_failed_login",
                raw_message=raw_message,
                source_ip="10.0.0.5",
                username="admin",
                metadata={"port": str(port)},
            )
            print(
                f"[agent] Event {i + 1}/{count} ingested with id={log_id} "
                f"at {event_time.isoformat()}"
            )
        except AgentError as exc:
            print(f"[agent] ERROR sending log event {i + 1}/{count}: {exc}")
            return

    print("[agent] Burst completed. Check alerts in admin or /api/alerts/.")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SIEM-Lite Agent CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # send-test-event command
    subparsers.add_parser(
        "send-test-event",
        help="Send a single synthetic ssh_failed_login event to the SIEM backend.",
    )

    # send-burst command
    burst_parser = subparsers.add_parser(
        "send-burst",
        help="Send multiple ssh_failed_login events to trigger brute-force rules.",
    )
    burst_parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Number of events to send (default: 5).",
    )
    burst_parser.add_argument(
        "--window",
        type=int,
        default=5,
        help="Time window in minutes over which to spread events (default: 5).",
    )

    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.command == "send-test-event":
        cmd_send_test_event()
    elif args.command == "send-burst":
        cmd_send_burst(count=args.count, window_minutes=args.window)
    else:
        parser.error(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
