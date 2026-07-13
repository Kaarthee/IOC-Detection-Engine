import datetime
import re
from dataclasses import asdict, dataclass


@dataclass
class SecurityEvent:
    """Normalized security event shared across log sources."""

    timestamp: str | None
    source_ip: str
    event_type: str
    username: str | None
    source: str
    destination_port: int | None
    protocol: str
    raw_log: str

    def to_dict(self) -> dict:
        """Convert the event into a serializable dictionary."""
        return asdict(self)


def parse_ubuntu_timestamp(
    log: str,
) -> str | None:
    """Convert an Ubuntu syslog timestamp into ISO 8601 format."""
    pattern = re.compile(
        r"^(?P<month>[A-Z][a-z]{2})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})"
    )

    match = pattern.search(log)

    if not match:
        return None

    timestamp_text = (
        f"{datetime.datetime.now().year} "
        f"{match.group('month')} "
        f"{match.group('day')} "
        f"{match.group('time')}"
    )

    try:
        parsed = datetime.datetime.strptime(
            timestamp_text,
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None

    return parsed.isoformat()


def normalize_ubuntu_auth_log(
    log: str,
) -> SecurityEvent | None:
    """Normalize one Ubuntu SSH authentication log entry."""
    failed_pattern = re.compile(
        r"Failed password for "
        r"(?P<invalid>invalid user )?"
        r"(?P<username>\S+) "
        r"from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}) "
        r"port (?P<port>\d+)"
    )

    accepted_pattern = re.compile(
        r"Accepted password for "
        r"(?P<username>\S+) "
        r"from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}) "
        r"port (?P<port>\d+)"
    )

    failed_match = failed_pattern.search(log)
    accepted_match = accepted_pattern.search(log)

    if failed_match:
        return SecurityEvent(
            timestamp=parse_ubuntu_timestamp(log),
            source_ip=failed_match.group("source_ip"),
            event_type="authentication_failure",
            username=failed_match.group("username"),
            source="ubuntu_auth",
            destination_port=int(
                failed_match.group("port")
            ),
            protocol="ssh",
            raw_log=log.strip(),
        )

    if accepted_match:
        return SecurityEvent(
            timestamp=parse_ubuntu_timestamp(log),
            source_ip=accepted_match.group("source_ip"),
            event_type="authentication_success",
            username=accepted_match.group("username"),
            source="ubuntu_auth",
            destination_port=int(
                accepted_match.group("port")
            ),
            protocol="ssh",
            raw_log=log.strip(),
        )

    return None


def normalize_ubuntu_auth_logs(
    logs: list[str],
) -> list[SecurityEvent]:
    """Normalize all supported Ubuntu authentication logs."""
    events: list[SecurityEvent] = []

    for log in logs:
        event = normalize_ubuntu_auth_log(log)

        if event is not None:
            events.append(event)

    return events

def group_events_by_source_ip(
    events: list[SecurityEvent],
) -> dict[str, list[SecurityEvent]]:
    """Group normalized security events by source IP."""
    grouped_events: dict[
        str,
        list[SecurityEvent],
    ] = {}

    for event in events:
        grouped_events.setdefault(
            event.source_ip,
            [],
        ).append(event)

    return grouped_events


def create_normalized_event_windows(
    events: list[SecurityEvent],
    window_minutes: int = 5,
) -> list[list[SecurityEvent]]:
    """Group normalized events into fixed time windows."""
    parsed_events: list[
        tuple[datetime.datetime, SecurityEvent]
    ] = []

    unparsed_events: list[SecurityEvent] = []

    for event in events:
        if event.timestamp is None:
            unparsed_events.append(event)
            continue

        try:
            parsed_timestamp = (
                datetime.datetime.fromisoformat(
                    event.timestamp
                )
            )
        except ValueError:
            unparsed_events.append(event)
            continue

        parsed_events.append(
            (
                parsed_timestamp,
                event,
            )
        )

    parsed_events.sort(
        key=lambda item: item[0]
    )

    windows: list[list[SecurityEvent]] = []
    current_window: list[SecurityEvent] = []
    window_start: datetime.datetime | None = None

    for timestamp, event in parsed_events:
        if window_start is None:
            window_start = timestamp
            current_window = [event]
            continue

        time_difference = (
            timestamp - window_start
        )

        if time_difference <= datetime.timedelta(
            minutes=window_minutes
        ):
            current_window.append(event)
        else:
            windows.append(current_window)
            current_window = [event]
            window_start = timestamp

    if current_window:
        windows.append(current_window)

    for event in unparsed_events:
        windows.append([event])

    return windows


def count_normalized_events(
    events: list[SecurityEvent],
) -> tuple[int, int]:
    """Count normalized authentication failures and successes."""
    failed = sum(
        1
        for event in events
        if event.event_type
        == "authentication_failure"
    )

    successful = sum(
        1
        for event in events
        if event.event_type
        == "authentication_success"
    )

    return failed, successful


def normalized_events_to_raw_logs(
    events: list[SecurityEvent],
) -> list[str]:
    """Return original raw logs for alert evidence."""
    return [
        event.raw_log
        for event in events
    ]
