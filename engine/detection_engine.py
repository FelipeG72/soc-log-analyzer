from detections.unauthorized_share import detect_unauthorized_share


DETECTION_RULES = [
    detect_unauthorized_share
]


def run_detections(event):
    alerts = []

    for detection_rule in DETECTION_RULES:
        alert = detection_rule(event)

        if alert:
            alerts.append(alert)

    return alerts

if __name__ == "__main__":
    sample_event = {
        "event_id": 5145,
        "result": "failure",
        "username": "sophia.rossi",
        "domain": "GSF-LAB",
        "source_ip": "192.168.56.20",
        "share_name": r"\\*\Executives"
    }

    results = run_detections(sample_event)

    for alert in results:
        print(f"[{alert['severity']}] {alert['title']}")
        print(alert["description"])