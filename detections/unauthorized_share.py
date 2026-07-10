def detect_unauthorized_share(event):
    if (
        event.get("event_id") == 5145
        and event.get("result") == "failure"
        and "Executives" in event.get("share_name", "")
    ):
        return {
            "title": "Unauthorized Executive Share Access",
            "severity": "HIGH",
            "description": (
                f"{event.get('domain')}\\{event.get('username')} "
                f"attempted to access {event.get('share_name')} "
                f"from {event.get('source_ip')}."
            ),
            "mitre": "T1039 - Data from Network Shared Drive",
            "recommendation": (
                "Verify whether the access attempt was authorized and "
                "review the user's recent activity."
            )
        }

    return None

if __name__ == "__main__":
    sample_event = {
        "event_id": 5145,
        "result": "failure",
        "username": "sophia.rossi",
        "domain": "GSF-LAB",
        "source_ip": "192.168.56.20",
        "share_name": r"\\*\Executives"
    }

    alert = detect_unauthorized_share(sample_event)
    print(alert)