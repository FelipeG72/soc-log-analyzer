import re
from collections import defaultdict
from datetime import datetime


LOG_FILE = "sample_logs/auth.log"
REPORT_FILE = "reports/alerts_report.txt"

FAILED_LOGIN_THRESHOLD = 5


def parse_failed_login(line):
    pattern = r"Failed password for (\w+) from ([\d.]+)"
    match = re.search(pattern, line)

    if match:
        username = match.group(1)
        ip_address = match.group(2)
        return username, ip_address

    return None


def detect_brute_force(log_lines):
    failed_attempts = defaultdict(int)
    alerts = []

    for line in log_lines:
        result = parse_failed_login(line)

        if result:
            username, ip_address = result
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
            username, ip_address = failed
            failed_ips.add(ip_address)

        success_pattern = r"Accepted password for (\w+) from ([\d.]+)"
        success = re.search(success_pattern, line)

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

    suspicious_keywords = [
        "powershell",
        "-encodedcommand",
        "invoke-expression",
        "downloadstring",
        "iex"
    ]

    for line in log_lines:
        lower_line = line.lower()

        if any(keyword in lower_line for keyword in suspicious_keywords):
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

    patterns = [
        "new user",
        "user created",
        "admin created",
        "added user"
    ]

    for line in log_lines:
        lower_line = line.lower()

        if any(pattern in lower_line for pattern in patterns):
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


def generate_report(alerts):
    with open(REPORT_FILE, "w") as report:
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


def main():
    print("=== SOC Log Analyzer ===")

    with open(LOG_FILE, "r") as file:
        log_lines = file.readlines()

    alerts = []
    alerts.extend(detect_brute_force(log_lines))
    alerts.extend(detect_success_after_failures(log_lines))
    alerts.extend(detect_suspicious_powershell(log_lines))
    alerts.extend(detect_user_creation(log_lines))
    alerts.extend(detect_port_scan(log_lines))

    generate_report(alerts)

    print(f"Total alerts generated: {len(alerts)}")
    print(f"Report exported to: {REPORT_FILE}")

    for alert in alerts:
        print(f"[{alert['severity']}] {alert['title']}")


if __name__ == "__main__":
    main()