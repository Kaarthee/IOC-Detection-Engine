import csv
import datetime
import json
import re
from collections import defaultdict
from pathlib import Path

# -------- COLORS --------
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# -------- CONFIG --------
IOC_FILE = Path("data/iocs.json")
LOG_FILE = Path("logs/sample-auth.log")
ALERT_FILE = Path("alerts/alerts.csv")
INCIDENT_FILE = Path("alerts/incidents.json")

FEED_SOURCE = "Local IOC JSON"
MAX_LOG_DISPLAY = 5
BRUTE_FORCE_THRESHOLD = 5
CORRELATION_WINDOW_MINUTES = 5


def load_iocs(ioc_file: Path) -> set[str]:
    """Load malicious IP addresses from the local IOC JSON feed."""
    try:
        with ioc_file.open("r", encoding="utf-8") as file:
            data = json.load(file)

        malicious_ips = data.get("malicious_ips", [])

        if not isinstance(malicious_ips, list):
            raise ValueError("'malicious_ips' must be a list")

        return set(malicious_ips)

    except FileNotFoundError:
        print(f"{RED}Error: IOC file not found: {ioc_file}{RESET}")
        raise SystemExit(1)

    except (json.JSONDecodeError, ValueError) as error:
        print(f"{RED}Error: Invalid IOC file: {error}{RESET}")
        raise SystemExit(1)


def read_logs(log_file: Path) -> list[str]:
    """Read authentication log lines."""
    try:
        with log_file.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file:
            return file.readlines()

    except FileNotFoundError:
        print(f"{RED}Error: Log file not found: {log_file}{RESET}")
        raise SystemExit(1)


def extract_ip_logs(log_lines: list[str]) -> dict[str, list[str]]:
    """Group relevant authentication log entries by source IP address."""
    ip_pattern = re.compile(
        r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)"
        r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
    )

    grouped_logs: dict[str, list[str]] = defaultdict(list)

    for line in log_lines:
        if (
            "Failed password" not in line
            and "Accepted password" not in line
        ):
            continue

        for ip in ip_pattern.findall(line):
            grouped_logs[ip].append(line.strip())

    return grouped_logs


def parse_log_timestamp(log: str) -> datetime.datetime | None:
    """Parse a standard Ubuntu syslog timestamp."""
    timestamp_pattern = re.compile(
        r"^(?P<month>[A-Z][a-z]{2})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})"
    )

    match = timestamp_pattern.search(log)

    if not match:
        return None

    timestamp_text = (
        f"{datetime.datetime.now().year} "
        f"{match.group('month')} "
        f"{match.group('day')} "
        f"{match.group('time')}"
    )

    try:
        return datetime.datetime.strptime(
            timestamp_text,
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None


def create_incident_windows(
    logs: list[str],
) -> list[list[str]]:
    """Group log entries into incidents using a fixed time window."""
    parsed_logs: list[tuple[datetime.datetime, str]] = []
    unparsed_logs: list[str] = []

    for log in logs:
        timestamp = parse_log_timestamp(log)

        if timestamp is not None:
            parsed_logs.append((timestamp, log))
        else:
            unparsed_logs.append(log)

    parsed_logs.sort(key=lambda item: item[0])

    incidents: list[list[str]] = []
    current_incident: list[str] = []
    window_start: datetime.datetime | None = None

    for timestamp, log in parsed_logs:
        if window_start is None:
            window_start = timestamp
            current_incident = [log]
            continue

        time_difference = timestamp - window_start

        if time_difference <= datetime.timedelta(
            minutes=CORRELATION_WINDOW_MINUTES
        ):
            current_incident.append(log)
        else:
            incidents.append(current_incident)
            current_incident = [log]
            window_start = timestamp

    if current_incident:
        incidents.append(current_incident)

    for log in unparsed_logs:
        incidents.append([log])

    return incidents


def count_events(logs: list[str]) -> tuple[int, int]:
    """Count failed and successful SSH authentication events."""
    failed = 0
    successful = 0
    repeat_pattern = re.compile(r"message repeated (\d+) times")

    for log in logs:
        if "Failed password" in log:
            match = repeat_pattern.search(log)

            if match:
                failed += int(match.group(1))
            else:
                failed += 1

        if "Accepted password" in log:
            successful += 1

    return failed, successful


def classify_activity(
    failed: int,
    successful: int,
    is_ioc_match: bool,
) -> tuple[str, str, str, str]:
    """
    Return severity, classification, MITRE ATT&CK mapping
    and display colour.
    """
    if failed > 0 and successful > 0:
        severity = "CRITICAL"
        classification = "Brute Force → Successful Login"
        mitre = "T1110, T1078"
        colour = YELLOW

    elif failed >= BRUTE_FORCE_THRESHOLD:
        severity = "HIGH"
        classification = "SSH Brute Force"
        mitre = "T1110"
        colour = RED

    elif successful > 0 and is_ioc_match:
        severity = "CRITICAL"
        classification = "Known IOC Successful Login"
        mitre = "T1078"
        colour = YELLOW

    elif successful > 0:
        severity = "LOW"
        classification = "Successful Login"
        mitre = "T1078"
        colour = GREEN

    elif failed > 0 and is_ioc_match:
        severity = "HIGH"
        classification = "IOC-Matched Login Failures"
        mitre = "T1110"
        colour = RED

    elif failed > 0:
        severity = "MEDIUM"
        classification = "Login Failures"
        mitre = "T1110"
        colour = CYAN

    else:
        severity = "INFO"
        classification = "No Relevant Activity"
        mitre = "N/A"
        colour = CYAN

    return severity, classification, mitre, colour


def should_alert(
    failed: int,
    successful: int,
    is_ioc_match: bool,
) -> bool:
    """Determine whether the activity should generate an alert."""
    return failed > 0 or is_ioc_match


def write_csv_header(alert_file: Path) -> None:
    """Create the alert CSV file and write its header."""
    alert_file.parent.mkdir(parents=True, exist_ok=True)

    with alert_file.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(
            [
                "Alert ID",
                "Timestamp",
                "IP",
                "IOC Match",
                "IOC Source",
                "Failed Attempts",
                "Successful Logins",
                "Severity",
                "Classification",
                "MITRE ATT&CK",
                "Evidence",
            ]
        )


def append_alert(
    alert_file: Path,
    alert_id: int,
    timestamp: str,
    ip: str,
    is_ioc_match: bool,
    failed: int,
    successful: int,
    severity: str,
    classification: str,
    mitre: str,
    logs: list[str],
) -> None:
    """Append a structured alert to the CSV file."""
    with alert_file.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(
            [
                alert_id,
                timestamp,
                ip,
                "Yes" if is_ioc_match else "No",
                FEED_SOURCE if is_ioc_match else "N/A",
                failed,
                successful,
                severity,
                classification,
                mitre,
                " | ".join(logs),
            ]
        )


def print_alert(
    alert_id: int,
    ip: str,
    is_ioc_match: bool,
    failed: int,
    successful: int,
    severity: str,
    classification: str,
    mitre: str,
    colour: str,
    logs: list[str],
) -> None:
    """Display a readable alert in the terminal."""
    print(f"{colour}{'=' * 60}{RESET}")
    print(f"{colour}ALERT #{alert_id}{RESET}")
    print(f"{colour}{'-' * 60}{RESET}")

    print(f"{CYAN}Source IP:{RESET} {ip}")
    print(
        f"{CYAN}IOC Match:{RESET} "
        f"{'Yes' if is_ioc_match else 'No'}"
    )
    print(
        f"{CYAN}IOC Source:{RESET} "
        f"{FEED_SOURCE if is_ioc_match else 'N/A'}"
    )
    print(f"{CYAN}Failed Attempts:{RESET} {failed}")
    print(f"{CYAN}Successful Logins:{RESET} {successful}")
    print(f"{CYAN}Severity:{RESET} {severity}")
    print(f"{CYAN}Classification:{RESET} {classification}")
    print(f"{CYAN}MITRE ATT&CK:{RESET} {mitre}")

    print(
        f"\n{CYAN}Evidence — last "
        f"{MAX_LOG_DISPLAY} entries:{RESET}"
    )

    for log in logs[-MAX_LOG_DISPLAY:]:
        print(f"  - {log}")

    if len(logs) > MAX_LOG_DISPLAY:
        hidden_count = len(logs) - MAX_LOG_DISPLAY
        print(
            f"{CYAN}... "
            f"({hidden_count} more logs hidden){RESET}"
        )

    print(f"{colour}{'=' * 60}{RESET}\n")


def get_incident_time_range(
    logs: list[str],
) -> tuple[str | None, str | None]:
    """Return the earliest and latest valid timestamps in an incident."""
    timestamps = [
        timestamp
        for log in logs
        if (timestamp := parse_log_timestamp(log)) is not None
    ]

    if not timestamps:
        return None, None

    timestamps.sort()

    return (
        timestamps[0].isoformat(),
        timestamps[-1].isoformat(),
    )


def build_incident_record(
    alert_id: int,
    generated_at: str,
    ip: str,
    is_ioc_match: bool,
    failed: int,
    successful: int,
    severity: str,
    classification: str,
    mitre: str,
    logs: list[str],
) -> dict:
    """Build a structured JSON incident record."""
    start_time, end_time = get_incident_time_range(logs)

    return {
        "incident_id": f"INC-{alert_id:04d}",
        "generated_at": generated_at,
        "source_ip": ip,
        "ioc": {
            "matched": is_ioc_match,
            "source": FEED_SOURCE if is_ioc_match else None,
        },
        "time_window": {
            "start": start_time,
            "end": end_time,
            "window_minutes": CORRELATION_WINDOW_MINUTES,
        },
        "event_counts": {
            "failed_logins": failed,
            "successful_logins": successful,
            "total_events": len(logs),
        },
        "severity": severity,
        "classification": classification,
        "mitre_attack": [
            technique.strip()
            for technique in mitre.split(",")
            if technique.strip() and technique.strip() != "N/A"
        ],
        "evidence": logs,
    }


def write_incident_json(
    incident_file: Path,
    incidents: list[dict],
) -> None:
    """Write structured incident records to a JSON file."""
    incident_file.parent.mkdir(parents=True, exist_ok=True)

    with incident_file.open("w", encoding="utf-8") as file:
        json.dump(
            incidents,
            file,
            indent=4,
            ensure_ascii=False,
        )


def main() -> None:
    malicious_ips = load_iocs(IOC_FILE)
    log_lines = read_logs(LOG_FILE)
    ip_logs = extract_ip_logs(log_lines)

    print(
        f"{CYAN}========== "
        f"IOC Detection Engine v2 "
        f"=========={RESET}\n"
    )
    print(f"Log source: {LOG_FILE}")
    print(f"IOC source: {IOC_FILE}")
    print(f"Observed IPs: {len(ip_logs)}\n")

    write_csv_header(ALERT_FILE)

    alert_id = 1
    incident_records: list[dict] = []

    for ip, logs in ip_logs.items():
        is_ioc_match = ip in malicious_ips
        incident_windows = create_incident_windows(logs)

        for incident_number, incident_logs in enumerate(
            incident_windows,
            start=1,
        ):
            failed, successful = count_events(incident_logs)

            if not should_alert(
                failed,
                successful,
                is_ioc_match,
            ):
                continue

            severity, classification, mitre, colour = classify_activity(
                failed,
                successful,
                is_ioc_match,
            )

            timestamp = datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            print(
                f"{CYAN}Incident window: "
                f"{incident_number}/"
                f"{len(incident_windows)}{RESET}"
            )

            print_alert(
                alert_id,
                ip,
                is_ioc_match,
                failed,
                successful,
                severity,
                classification,
                mitre,
                colour,
                incident_logs,
            )

            append_alert(
                ALERT_FILE,
                alert_id,
                timestamp,
                ip,
                is_ioc_match,
                failed,
                successful,
                severity,
                classification,
                mitre,
                incident_logs,
            )

            incident_records.append(
                build_incident_record(
                    alert_id,
                    timestamp,
                    ip,
                    is_ioc_match,
                    failed,
                    successful,
                    severity,
                    classification,
                    mitre,
                    incident_logs,
                )
            )

            alert_id += 1

    write_incident_json(
        INCIDENT_FILE,
        incident_records,
    )

    generated_alerts = alert_id - 1

    print(f"{GREEN}Detection completed{RESET}")
    print(
        f"{GREEN}Alerts generated: "
        f"{generated_alerts}{RESET}"
    )
    print(f"{GREEN}CSV output: {ALERT_FILE}{RESET}")
    print(f"{GREEN}JSON output: {INCIDENT_FILE}{RESET}")


if __name__ == "__main__":
    main()
