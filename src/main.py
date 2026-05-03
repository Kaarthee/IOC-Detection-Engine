import json
import re
import csv
import datetime
from collections import defaultdict

# -------- COLORS --------
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# -------- CONFIG --------
IOC_FILE = "data/iocs.json"
LOG_FILE = "logs/sample-auth.log"
ALERT_FILE = "alerts/alerts.csv"
FEED_SOURCE = "Local IOC JSON"
MAX_LOG_DISPLAY = 5   # 👈 control congestion

# Load IOC
with open(IOC_FILE, "r") as file:
    malicious_ips = json.load(file)["malicious_ips"]

# Read logs
with open(LOG_FILE, "r") as file:
    log_lines = file.readlines()

# Patterns
ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
repeat_pattern = r"message repeated (\d+) times"

# Group logs
ip_logs = defaultdict(list)
for line in log_lines:
    for ip in re.findall(ip_pattern, line):
        ip_logs[ip].append(line.strip())

print(f"{CYAN}========== IOC Detection Engine =========={RESET}\n")

# CSV
with open(ALERT_FILE, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow([
        "Alert ID","Timestamp","IP","Failed Attempts",
        "Successful Logins","Severity","Type","Logs"
    ])

alert_id = 1

for ip, logs in ip_logs.items():
    if ip not in malicious_ips:
        continue

    failed = 0
    success = 0

    for log in logs:
        if "Failed password" in log:
            match = re.search(repeat_pattern, log)
            failed += int(match.group(1)) if match else 1
        if "Accepted password" in log:
            success += 1

    # Detection logic
    if success > 0 and failed > 0:
        severity = "CRITICAL"
        color = YELLOW
        dtype = "Brute Force → Successful Login"
    elif success > 0:
        severity = "CRITICAL"
        color = YELLOW
        dtype = "Valid Account Usage"
    elif failed >= 5:
        severity = "HIGH"
        color = RED
        dtype = "Brute Force"
    else:
        severity = "MEDIUM"
        color = CYAN
        dtype = "Login Failures"

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # -------- CLEAN PRINT --------
    print(f"{color}{'='*50}{RESET}")
    print(f"{color}🚨 ALERT #{alert_id}{RESET}")
    print(f"{color}{'-'*50}{RESET}")

    print(f"{CYAN}IP:{RESET} {ip}")
    print(f"{CYAN}Failed Attempts:{RESET} {failed}")
    print(f"{CYAN}Successful Logins:{RESET} {success}")
    print(f"{CYAN}Severity:{RESET} {severity}")
    print(f"{CYAN}Type:{RESET} {dtype}")

    print(f"\n{CYAN}--- Evidence (last {MAX_LOG_DISPLAY}) ---{RESET}")

    for log in logs[-MAX_LOG_DISPLAY:]:
        print(f"  - {log}")

    if len(logs) > MAX_LOG_DISPLAY:
        print(f"{CYAN}... ({len(logs)-MAX_LOG_DISPLAY} more logs hidden){RESET}")

    print(f"{color}{'='*50}{RESET}\n")

    # Save CSV (full logs)
    with open(ALERT_FILE, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            alert_id, timestamp, ip, failed, success, severity, dtype,
            " | ".join(logs)
        ])

    alert_id += 1

print(f"{GREEN}✔ Detection Completed{RESET}")
