from typing import Any


def create_alert(
    *,
    title: str,
    severity: str,
    description: str,
    mitre: str,
    recommendation: str,
    event: dict[str, Any],
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "mitre": mitre,
        "recommendation": recommendation,
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "computer": event.get("computer"),
        "username": event.get("username"),
        "source_ip": event.get("source_ip"),
    }


def detect_kerberos_failure(
    event: dict[str, Any],
) -> list[dict[str, Any]]:
    if event.get("event_id") != 4771:
        return []

    status = str(event.get("status") or "").strip().lower()

    if status != "0x18":
        return []

    username = event.get("username") or "Unknown"
    source_ip = event.get("source_ip") or "Unknown"
    computer = event.get("computer") or "Unknown"

    return [
        create_alert(
            title="Kerberos Authentication Failure",
            severity="MEDIUM",
            description=(
                f"Incorrect password attempt detected for "
                f"'{username}' from {source_ip} against {computer}."
            ),
            mitre="T1110 - Brute Force",
            recommendation=(
                "Review repeated failures for this user and source IP. "
                "Investigate possible brute-force or password-spraying activity."
            ),
            event=event,
        )
    ]


def detect_failed_logon(
    event: dict[str, Any],
) -> list[dict[str, Any]]:
    if event.get("event_id") != 4625:
        return []

    status = str(event.get("status") or "").strip().lower()
    sub_status = str(event.get("sub_status") or "").strip().lower()

    wrong_password_codes = {"0xc000006a"}
    unknown_user_codes = {"0xc0000064"}

    if (
        status in wrong_password_codes
        or sub_status in wrong_password_codes
    ):
        description = "Incorrect password used for an existing Windows account."
        severity = "MEDIUM"

    elif (
        status in unknown_user_codes
        or sub_status in unknown_user_codes
    ):
        description = "Authentication attempted with an unknown username."
        severity = "MEDIUM"

    else:
        return []

    username = event.get("username") or "Unknown"
    source_ip = event.get("source_ip") or "Unknown"

    return [
        create_alert(
            title="Windows Failed Logon",
            severity=severity,
            description=(
                f"{description} User: '{username}'. Source: {source_ip}."
            ),
            mitre="T1110 - Brute Force",
            recommendation=(
                "Review nearby authentication failures and validate the source."
            ),
            event=event,
        )
    ]


def run_event_rules(
    event: dict[str, Any],
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []

    alerts.extend(detect_kerberos_failure(event))
    alerts.extend(detect_failed_logon(event))

    return alerts