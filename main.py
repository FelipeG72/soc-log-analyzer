import re
import argparse
import json
import csv
from collections import defaultdict
from datetime import datetime
from parsers.windows_parser import parse_windows_event
from detections.unauthorized_share import detect_unauthorized_share


FAILED_LOGIN_THRESHOLD = 5


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Analyze log files for suspicious security activity."
    )

    parser.add_argument("--log", help="Path to the log file to analyze")
    parser.add_argument("--report", default="reports/alerts_report.txt", help="Path for TXT report")
    parser.add_argument("--json", default="reports/alerts_report.json", help="Path for JSON report")
    parser.add_argument("--csv", default="reports/alerts_report.csv", help="Path for CSV report")
    parser.add_argument(
    "--windows-xml",
    help="Path to an exported Windows Event XML file"
    )

    return parser.parse_args()


def parse_timestamp(line):
    pattern = r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    match = re.search(pattern, line)

    if match:
        return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")

    return None


def parse_failed_login(line):
    pattern = r"Failed password for (\w+) from ([\d.]+)"
    match = re.search(pattern, line)

    if match:
        return match.group(1), match.group(2), parse_timestamp(line)

    return None


def parse_log_line(line):
    timestamp = parse_timestamp(line)
    lower_line = line.lower()

    failed_login = re.search(r"Failed password for (\w+) from ([\d.]+)", line)
    if failed_login:
        return {
            "timestamp": timestamp,
            "event_type": "failed_login",
            "username": failed_login.group(1),
            "ip_address": failed_login.group(2),
            "raw": line.strip()
        }

    successful_login = re.search(r"Accepted password for (\w+) from ([\d.]+)", line)
    if successful_login:
        return {
            "timestamp": timestamp,
            "event_type": "successful_login",
            "username": successful_login.group(1),
            "ip_address": successful_login.group(2),
            "raw": line.strip()
        }

    if any(keyword in lower_line for keyword in ["powershell", "-encodedcommand", "invoke-expression", "downloadstring", "iex"]):
        return {
            "timestamp": timestamp,
            "event_type": "suspicious_powershell",
            "username": None,
            "ip_address": None,
            "raw": line.strip()
        }

    if any(keyword in lower_line for keyword in ["new user", "user created", "admin created", "added user"]):
        return {
            "timestamp": timestamp,
            "event_type": "user_created",
            "username": None,
            "ip_address": None,
            "raw": line.strip()
        }

    if "nmap" in lower_line or "scan detected" in lower_line:
        return {
            "timestamp": timestamp,
            "event_type": "port_scan",
            "username": None,
            "ip_address": None,
            "raw": line.strip()
        }

    return None


def parse_log_file(log_lines):
    events = []

    for line in log_lines:
        event = parse_log_line(line)
        if event:
            events.append(event)

    return events


def detect_brute_force(log_lines):
    failed_attempts = defaultdict(int)
    alerts = []

    for line in log_lines:
        result = parse_failed_login(line)

        if result:
            username, ip_address, timestamp = result
            failed_attempts[(username, ip_address)] += 1

    for (username, ip_address), count in failed_attempts.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "title": "Possible Brute Force Attack",
                "severity": "HIGH",
                "description": f"{count} failed login attempts detected for user '{username}' from {ip_address}.",
                "mitre": "T1110 - Brute Force",
                "recommendation": "Block suspicious IP, review authentication logs, enforce MFA."
            })

    return alerts


def detect_success_after_failures(log_lines):
    failed_ips = set()
    alerts = []

    for line in log_lines:
        failed = parse_failed_login(line)

        if failed:
            username, ip_address, timestamp = failed
            failed_ips.add(ip_address)

        success = re.search(r"Accepted password for (\w+) from ([\d.]+)", line)

        if success:
            username = success.group(1)
            ip_address = success.group(2)

            if ip_address in failed_ips:
                alerts.append({
                    "title": "Successful Login After Failed Attempts",
                    "severity": "CRITICAL",
                    "description": f"Successful login for '{username}' from {ip_address} after failed attempts.",
                    "mitre": "T1110 - Brute Force / Valid Accounts",
                    "recommendation": "Investigate account compromise, reset credentials, review session activity."
                })

    return alerts


def detect_suspicious_powershell(log_lines):
    alerts = []
    suspicious_keywords = ["powershell", "-encodedcommand", "invoke-expression", "downloadstring", "iex"]

    for line in log_lines:
        if any(keyword in line.lower() for keyword in suspicious_keywords):
            alerts.append({
                "title": "Suspicious PowerShell Activity",
                "severity": "HIGH",
                "description": line.strip(),
                "mitre": "T1059.001 - PowerShell",
                "recommendation": "Review command execution, check endpoint telemetry, investigate user context."
            })

    return alerts


def detect_user_creation(log_lines):
    alerts = []
    patterns = ["new user", "user created", "admin created", "added user"]

    for line in log_lines:
        if any(pattern in line.lower() for pattern in patterns):
            alerts.append({
                "title": "New User Account Created",
                "severity": "MEDIUM",
                "description": line.strip(),
                "mitre": "T1136 - Create Account",
                "recommendation": "Verify whether account creation was authorized."
            })

    return alerts


def detect_port_scan(log_lines):
    alerts = []

    for line in log_lines:
        if "nmap" in line.lower() or "scan detected" in line.lower():
            alerts.append({
                "title": "Possible Port Scan Detected",
                "severity": "MEDIUM",
                "description": line.strip(),
                "mitre": "T1046 - Network Service Discovery",
                "recommendation": "Review source IP activity and firewall logs."
            })

    return alerts


def generate_report(alerts, report_file):
    with open(report_file, "w") as report:
        report.write("SOC Log Analyzer Alert Report\n")
        report.write("=" * 40 + "\n")
        report.write(f"Generated: {datetime.now()}\n\n")

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


def export_json(alerts, json_file):
    with open(json_file, "w") as file:
        json.dump(alerts, file, indent=4)


def export_csv(alerts, csv_file):
    fieldnames = ["title", "severity", "description", "mitre", "recommendation"]

    with open(csv_file, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)


def main():
    args = parse_arguments()
    if args.windows_xml:
        event = parse_windows_event(args.windows_xml)
        alert = detect_unauthorized_share(event)

    if alert:
        alerts = [alert]

        generate_report(alerts, args.report)
        export_json(alerts, args.json)
        export_csv(alerts, args.csv)

        print(f"[{alert['severity']}] {alert['title']}")
        print(alert["description"])
        print(f"Report exported to: {args.report}")
        return

    print("No suspicious Windows events detected.")
    return
            
    if not args.log and not args.windows_xml:
        raise SystemExit("Provide either --log or --windows-xml.")

    print("=== SOC Log Analyzer ===")
    print(f"Analyzing: {args.log}")

    with open(args.log, "r") as file:
        log_lines = file.readlines()

    events = parse_log_file(log_lines)
    print(f"Parsed events: {len(events)}")

    alerts = []
    alerts.extend(detect_brute_force(log_lines))
    alerts.extend(detect_success_after_failures(log_lines))
    alerts.extend(detect_suspicious_powershell(log_lines))
    alerts.extend(detect_user_creation(log_lines))
    alerts.extend(detect_port_scan(log_lines))

    generate_report(alerts, args.report)
    export_json(alerts, args.json)
    export_csv(alerts, args.csv)

    print(f"Total alerts generated: {len(alerts)}")
    print(f"Report exported to: {args.report}")
    print(f"JSON exported to: {args.json}")
    print(f"CSV exported to: {args.csv}")

    for alert in alerts:
        print(f"[{alert['severity']}] {alert['title']}")


if __name__ == "__main__":
    main()