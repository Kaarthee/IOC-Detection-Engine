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

FEED_SOURCE = "Local IOC JSON"
MAX_LOG_DISPLAY = 5
BRUTE_FORCE_THRESHOLD = 5


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
        with log_file.open("r", encoding="utf-8", errors="replace") as file:
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
        if "Failed password" not in line and "Accepted password" not in line:
            continue

        for ip in ip_pattern.findall(line):
            grouped_logs[ip].append(line.strip())

    return grouped_logs


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
    Return severity, classification, MITRE ATT&CK mapping and display colour.
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
    return (
        failed > 0
        or is_ioc_match
        or (failed > 0 and successful > 0)
    )


def write_csv_header(alert_file: Path) -> None:
    """Create the alert CSV file and write its header."""
    alert_file.parent.mkdir(parents=True, exist_ok=True)

    with alert_file.open("w", newline="", encoding="utf-8") as csvfile:
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
    with alert_file.open("a", newline="", encoding="utf-8") as csvfile:
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

    print(f"\n{CYAN}Evidence — last {MAX_LOG_DISPLAY} entries:{RESET}")

    for log in logs[-MAX_LOG_DISPLAY:]:
        print(f"  - {log}")

    if len(logs) > MAX_LOG_DISPLAY:
        hidden_count = len(logs) - MAX_LOG_DISPLAY
        print(f"{CYAN}... ({hidden_count} more logs hidden){RESET}")

    print(f"{colour}{'=' * 60}{RESET}\n")


def main() -> None:
    malicious_ips = load_iocs(IOC_FILE)
    log_lines = read_logs(LOG_FILE)
    ip_logs = extract_ip_logs(log_lines)

    print(f"{CYAN}========== IOC Detection Engine v2 =========={RESET}\n")
    print(f"Log source: {LOG_FILE}")
    print(f"IOC source: {IOC_FILE}")
    print(f"Observed IPs: {len(ip_logs)}\n")

    write_csv_header(ALERT_FILE)

    alert_id = 1

    for ip, logs in ip_logs.items():
        failed, successful = count_events(logs)
        is_ioc_match = ip in malicious_ips

        if not should_alert(failed, successful, is_ioc_match):
            continue

        severity, classification, mitre, colour = classify_activity(
            failed,
            successful,
            is_ioc_match,
        )

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
            logs,
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
            logs,
        )

        alert_id += 1

    generated_alerts = alert_id - 1

    print(f"{GREEN}Detection completed{RESET}")
    print(f"{GREEN}Alerts generated: {generated_alerts}{RESET}")
    print(f"{GREEN}CSV output: {ALERT_FILE}{RESET}")


if __name__ == "__main__":
    main()
