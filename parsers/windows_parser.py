import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


WINDOWS_EVENT_NAMESPACE = {
    "evt": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def clean_ip_address(ip_address: str | None) -> str | None:
    if not ip_address:
        return None

    return ip_address.removeprefix("::ffff:")


def parse_event_element(event_element: ET.Element) -> dict[str, Any]:
    system = event_element.find("evt:System", WINDOWS_EVENT_NAMESPACE)
    event_data_element = event_element.find(
        "evt:EventData",
        WINDOWS_EVENT_NAMESPACE,
    )

    if system is None:
        raise ValueError("Windows event is missing the System element.")

    event_id_element = system.find(
        "evt:EventID",
        WINDOWS_EVENT_NAMESPACE,
    )
    computer_element = system.find(
        "evt:Computer",
        WINDOWS_EVENT_NAMESPACE,
    )
    time_created_element = system.find(
        "evt:TimeCreated",
        WINDOWS_EVENT_NAMESPACE,
    )

    raw_data: dict[str, str] = {}

    if event_data_element is not None:
        for data_element in event_data_element.findall(
            "evt:Data",
            WINDOWS_EVENT_NAMESPACE,
        ):
            field_name = data_element.get("Name")

            if field_name:
                raw_data[field_name] = data_element.text or ""

    event_id = None

    if event_id_element is not None and event_id_element.text:
        event_id = int(event_id_element.text)

    username = (
        raw_data.get("TargetUserName")
        or raw_data.get("SubjectUserName")
        or raw_data.get("AccountName")
    )

    source_ip = clean_ip_address(
        raw_data.get("IpAddress")
        or raw_data.get("SourceNetworkAddress")
        or raw_data.get("ClientAddress")
    )

    status = (
        raw_data.get("Status")
        or raw_data.get("FailureCode")
        or raw_data.get("SubStatus")
    )

    return {
        "event_id": event_id,
        "timestamp": (
            time_created_element.get("SystemTime")
            if time_created_element is not None
            else None
        ),
        "computer": (
            computer_element.text
            if computer_element is not None
            else None
        ),
        "username": username,
        "target_username": raw_data.get("TargetUserName"),
        "domain": (
            raw_data.get("TargetDomainName")
            or raw_data.get("SubjectDomainName")
        ),
        "source_ip": source_ip,
        "source_port": (
            raw_data.get("IpPort")
            or raw_data.get("SourcePort")
        ),
        "status": status,
        "sub_status": raw_data.get("SubStatus"),
        "failure_reason": raw_data.get("FailureReason"),
        "logon_type": raw_data.get("LogonType"),
        "workstation": raw_data.get("WorkstationName"),
        "service_name": raw_data.get("ServiceName"),
        "authentication_package": raw_data.get(
            "AuthenticationPackageName"
        ),
        "raw_data": raw_data,
    }


def parse_windows_events(file_path: str) -> list[dict[str, Any]]:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Windows XML file not found: {path}")

    try:
        tree = ET.parse(path)
    except ET.ParseError as error:
        raise ValueError(f"Invalid Windows XML: {error}") from error

    root = tree.getroot()

   
    if root.tag.endswith("Event"):
        return [parse_event_element(root)]

    
    event_elements = root.findall(
        ".//evt:Event",
        WINDOWS_EVENT_NAMESPACE,
    )

    return [
        parse_event_element(event_element)
        for event_element in event_elements
    ]