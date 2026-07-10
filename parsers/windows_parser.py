import xml.etree.ElementTree as ET


NAMESPACE = {
    "evt": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def parse_windows_event(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    event = root

    # Supports XML files wrapped in <Events>
    if root.tag.endswith("Events"):
        event = root.find("evt:Event", NAMESPACE)

    if event is None:
        raise ValueError("No Windows Event element was found in the XML file.")

    event_id_element = event.find("evt:System/evt:EventID", NAMESPACE)
    computer_element = event.find("evt:System/evt:Computer", NAMESPACE)
    time_element = event.find("evt:System/evt:TimeCreated", NAMESPACE)

    event_data = {}

    for data_element in event.findall("evt:EventData/evt:Data", NAMESPACE):
        field_name = data_element.get("Name")
        field_value = data_element.text or ""

        if field_name:
            event_data[field_name] = field_value

    parsed_event = {
        "source": "windows",
        "event_id": int(event_id_element.text),
        "timestamp": time_element.get("SystemTime"),
        "computer": computer_element.text,
        "username": event_data.get("SubjectUserName"),
        "domain": event_data.get("SubjectDomainName"),
        "source_ip": event_data.get("IpAddress"),
        "share_name": event_data.get("ShareName"),
        "share_local_path": event_data.get("ShareLocalPath"),
        "access_mask": event_data.get("AccessMask"),
        "result": "failure"
    }

    return parsed_event


if __name__ == "__main__":
    event = parse_windows_event("sample_logs/event_5145.xml")
    print(event)