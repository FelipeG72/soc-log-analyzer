import argparse
import csv
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from engine.detection_engine import run_detections_for_events
from parsers.windows_parser import parse_windows_events


FAILED_LOGIN_THRESHOLD = 5


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze Linux-style logs or exported Windows Event XML files."
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--log", help="Path to a text log file")
    input_group.add_argument(
        "--windows-xml",
        help="Path to an exported Windows Event XML file",
    )

    parser.add_argument(
        "--report",
        default="reports/alerts_report.txt",
        help="Path for the text report",
    )
    parser.add_argument(
        "--json",
        default="reports/alerts_report.json",
        help="Path for the JSON report",
    )
    parser.add_argument(
        "--csv",
        default="reports/alerts_report.csv",
        help="Path for the CSV report",
    )

    return parser.parse_args()


def parse_timestamp(line: str) -> datetime | None:
    match = re.search(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
        line,
    )

    if not match:
        return None

    return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")


def parse_failed_login(line: str) -> tuple[str, str, datetime | None] | None:
    match = re.search(
        r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)",
        line,
        re.IGNORECASE,
    )

    if not match:
        return None

    return match.group(1), match.group(2), parse_timestamp(line)


def parse_log_line(line: str) -> dict[str, Any] | None:
    timestamp = parse_timestamp(line)
    lower_line = line.lower()

    failed_login = re.search(
        r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)",
        line,
        re.IGNORECASE,
    )
    if failed_login:
        return {
            "timestamp": timestamp,
            "event_type": "failed_login",
            "username": failed_login.group(1),
            "ip_address": failed_login.group(2),
            "raw": line.strip(),
        }

    successful_login = re.search(
        r"Accepted password for (\S+) from ([\d.]+)",
        line,
        re.IGNORECASE,
    )
    if successful_login:
        return {
            "timestamp": timestamp,
            "event_type": "successful_login",
            "username": successful_login.group(1),
            "ip_address": successful_login.group(2),
            "raw": line.strip(),
        }

    suspicious_powershell_keywords = (
        "powershell",
        "-encodedcommand",
        "invoke-expression",
        "downloadstring",
        "iex",
    )
    if any(keyword in lower_line for keyword in suspicious_powershell_keywords):
        return {
            "timestamp": timestamp,
            "event_type": "suspicious_powershell",
            "username": None,
            "ip_address": None,
            "raw": line.strip(),
        }

    if any(
        keyword in lower_line
        for keyword in ("new user", "user created", "admin created", "added user")
    ):
        return {
            "timestamp": timestamp,
            "event_type": "user_created",
            "username": None,
            "ip_address": None,
            "raw": line.strip(),
        }

    if "nmap" in lower_line or "scan detected" in lower_line:
        return {
            "timestamp": timestamp,
            "event_type": "port_scan",
            "username": None,
            "ip_address": None,
            "raw": line.strip(),
        }

    return None


def parse_log_file(log_lines: list[str]) -> list[dict[str, Any]]:
    events = []

    for line in log_lines:
        event = parse_log_line(line)
        if event:
            events.append(event)

    return events


def build_alert(
    *,
    title: str,
    severity: str,
    description: str,
    mitre: str,
    recommendation: str,
) -> dict[str, str]:
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "mitre": mitre,
        "recommendation": recommendation,
    }


def detect_brute_force(log_lines: list[str]) -> list[dict[str, str]]:
    failed_attempts: defaultdict[tuple[str, str], int] = defaultdict(int)

    for line in log_lines:
        result = parse_failed_login(line)
        if not result:
            continue

        username, ip_address, _ = result
        failed_attempts[(username, ip_address)] += 1

    alerts = []

    for (username, ip_address), count in failed_attempts.items():
        if count < FAILED_LOGIN_THRESHOLD:
            continue

        alerts.append(
            build_alert(
                title="Possible Brute Force Attack",
                severity="HIGH",
                description=(
                    f"{count} failed login attempts detected for "
                    f"'{username}' from {ip_address}."
                ),
                mitre="T1110 - Brute Force",
                recommendation=(
                    "Review authentication logs, validate the source, "
                    "block malicious IPs, and enforce MFA."
                ),
            )
        )

    return alerts


def detect_success_after_failures(
    log_lines: list[str],
) -> list[dict[str, str]]:
    failed_pairs: set[tuple[str, str]] = set()
    alerts = []

    for line in log_lines:
        failed = parse_failed_login(line)
        if failed:
            username, ip_address, _ = failed
            failed_pairs.add((username, ip_address))
            continue

        success = re.search(
            r"Accepted password for (\S+) from ([\d.]+)",
            line,
            re.IGNORECASE,
        )
        if not success:
            continue

        username = success.group(1)
        ip_address = success.group(2)

        if (username, ip_address) in failed_pairs:
            alerts.append(
                build_alert(
                    title="Successful Login After Failed Attempts",
                    severity="CRITICAL",
                    description=(
                        f"Successful login for '{username}' from "
                        f"{ip_address} after previous failures."
                    ),
                    mitre="T1110 - Brute Force / T1078 - Valid Accounts",
                    recommendation=(
                        "Investigate possible account compromise, reset credentials, "
                        "review the session, and validate MFA status."
                    ),
                )
            )

    return alerts


def detect_suspicious_powershell(
    log_lines: list[str],
) -> list[dict[str, str]]:
    keywords = (
        "powershell",
        "-encodedcommand",
        "invoke-expression",
        "downloadstring",
        "iex",
    )

    return [
        build_alert(
            title="Suspicious PowerShell Activity",
            severity="HIGH",
            description=line.strip(),
            mitre="T1059.001 - PowerShell",
            recommendation=(
                "Review the command, user context, parent process, and endpoint telemetry."
            ),
        )
        for line in log_lines
        if any(keyword in line.lower() for keyword in keywords)
    ]


def detect_user_creation(log_lines: list[str]) -> list[dict[str, str]]:
    patterns = ("new user", "user created", "admin created", "added user")

    return [
        build_alert(
            title="New User Account Created",
            severity="MEDIUM",
            description=line.strip(),
            mitre="T1136 - Create Account",
            recommendation="Verify whether the account creation was authorized.",
        )
        for line in log_lines
        if any(pattern in line.lower() for pattern in patterns)
    ]


def detect_port_scan(log_lines: list[str]) -> list[dict[str, str]]:
    return [
        build_alert(
            title="Possible Port Scan Detected",
            severity="MEDIUM",
            description=line.strip(),
            mitre="T1046 - Network Service Discovery",
            recommendation="Review the source IP, firewall logs, and nearby activity.",
        )
        for line in log_lines
        if "nmap" in line.lower() or "scan detected" in line.lower()
    ]


def ensure_parent_directory(file_path: str) -> None:
    Path(file_path).parent.mkdir(parents=True, exist_ok=True)


def normalize_alert(alert: dict[str, Any]) -> dict[str, str]:
    return {
        "title": str(alert.get("title", "Untitled Alert")),
        "severity": str(alert.get("severity", "UNKNOWN")),
        "description": str(alert.get("description", "")),
        "mitre": str(
            alert.get("mitre")
            or alert.get("mitre_attack")
            or "Not mapped"
        ),
        "recommendation": str(
            alert.get("recommendation")
            or "Review the related event and investigate as needed."
        ),
    }


def normalize_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [normalize_alert(alert) for alert in alerts]


def generate_report(alerts: list[dict[str, str]], report_file: str) -> None:
    ensure_parent_directory(report_file)

    with open(report_file, "w", encoding="utf-8") as report:
        report.write("SOC Log Analyzer Alert Report\n")
        report.write("=" * 40 + "\n")
        report.write(f"Generated: {datetime.now().isoformat(timespec='seconds')}\n\n")

        if not alerts:
            report.write("No suspicious activity detected.\n")
            return

        for index, alert in enumerate(alerts, start=1):
            report.write(f"Alert #{index}\n")
            report.write(f"Title: {alert['title']}\n")
            report.write(f"Severity: {alert['severity']}\n")
            report.write(f"Description: {alert['description']}\n")
            report.write(f"MITRE ATT&CK: {alert['mitre']}\n")
            report.write(f"Recommendation: {alert['recommendation']}\n")
            report.write("-" * 40 + "\n")


def export_json(alerts: list[dict[str, str]], json_file: str) -> None:
    ensure_parent_directory(json_file)

    with open(json_file, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)


def export_csv(alerts: list[dict[str, str]], csv_file: str) -> None:
    ensure_parent_directory(csv_file)

    fieldnames = [
        "title",
        "severity",
        "description",
        "mitre",
        "recommendation",
    ]

    with open(csv_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)


def analyze_windows_xml(
    xml_path: str,
) -> tuple[int, list[dict[str, Any]]]:
    events = parse_windows_events(xml_path)
    alerts = run_detections_for_events(events)

    return len(events), alerts

def analyze_text_log(log_path: str) -> tuple[int, list[dict[str, str]]]:
    with open(log_path, "r", encoding="utf-8", errors="replace") as file:
        log_lines = file.readlines()

    events = parse_log_file(log_lines)

    alerts: list[dict[str, str]] = []
    alerts.extend(detect_brute_force(log_lines))
    alerts.extend(detect_success_after_failures(log_lines))
    alerts.extend(detect_suspicious_powershell(log_lines))
    alerts.extend(detect_user_creation(log_lines))
    alerts.extend(detect_port_scan(log_lines))

    return len(events), alerts


def print_alerts(alerts: list[dict[str, str]]) -> None:
    if not alerts:
        print("No suspicious activity detected.")
        return

    for alert in alerts:
        print(f"\n[{alert['severity']}] {alert['title']}")
        print(alert["description"])
        print(f"MITRE ATT&CK: {alert['mitre']}")
        print(f"Recommendation: {alert['recommendation']}")


def main() -> None:
    args = parse_arguments()

    try:
        if args.windows_xml:
            parsed_event_count, raw_alerts = analyze_windows_xml(args.windows_xml)
            source_path = args.windows_xml
            source_type = "Windows events"
        else:
            parsed_event_count, raw_alerts = analyze_text_log(args.log)
            source_path = args.log
            source_type = "log events"
    except FileNotFoundError as error:
        raise SystemExit(f"Input file not found: {error}") from error
    except (ValueError, OSError) as error:
        raise SystemExit(f"Analysis failed: {error}") from error

    alerts = normalize_alerts(raw_alerts)

    generate_report(alerts, args.report)
    export_json(alerts, args.json)
    export_csv(alerts, args.csv)

    print("=== SOC Log Analyzer ===")
    print(f"Analyzing: {source_path}")
    print(f"Parsed {source_type}: {parsed_event_count}")
    print(f"Total alerts generated: {len(alerts)}")

    print_alerts(alerts)

    print(f"\nTXT report: {args.report}")
    print(f"JSON report: {args.json}")
    print(f"CSV report: {args.csv}")


if __name__ == "__main__":
    main()