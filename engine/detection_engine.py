from collections import defaultdict
from typing import Any

from engine.rules import run_event_rules


KERBEROS_BRUTE_FORCE_THRESHOLD = 5


def run_detections(
    event: dict[str, Any],
) -> list[dict[str, Any]]:
    return run_event_rules(event)


def detect_repeated_kerberos_failures(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    failure_counts: defaultdict[tuple[str, str], int] = defaultdict(int)

    for event in events:
        if event.get("event_id") != 4771:
            continue

        status = str(event.get("status") or "").strip().lower()

        if status != "0x18":
            continue

        username = str(event.get("username") or "Unknown")
        source_ip = str(event.get("source_ip") or "Unknown")

        failure_counts[(username, source_ip)] += 1

    alerts = []

    for (username, source_ip), count in failure_counts.items():
        if count < KERBEROS_BRUTE_FORCE_THRESHOLD:
            continue

        alerts.append(
            {
                "title": "Possible Kerberos Brute Force Attack",
                "severity": "HIGH",
                "description": (
                    f"{count} incorrect-password Kerberos failures "
                    f"were detected for '{username}' from {source_ip}."
                ),
                "mitre": "T1110 - Brute Force",
                "recommendation": (
                    "Investigate the source system, review the targeted account, "
                    "reset credentials if necessary, and enforce MFA."
                ),
                "event_id": 4771,
                "username": username,
                "source_ip": source_ip,
            }
        )

    return alerts


def run_detections_for_events(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []

    for event in events:
        alerts.extend(run_detections(event))

    alerts.extend(detect_repeated_kerberos_failures(events))

    return alerts