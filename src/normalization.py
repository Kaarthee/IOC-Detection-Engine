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
