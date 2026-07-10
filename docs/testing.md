# Testing and Validation

## Testing Objective

The IOC Detection Engine was tested to confirm that it can:

- Read SSH authentication logs
- Extract source IP addresses
- Match IP addresses against a local IOC feed
- Count failed and successful login attempts
- Identify brute-force behaviour
- Detect successful login following repeated failures
- Assign severity levels
- Map activity to MITRE ATT&CK
- Save alerts to CSV

---

## Test Environment

### Detection System

- Operating System: Ubuntu Linux
- Hostname: Ubuntu-SSH-Lab
- Project path:

```text
/home/ubuntu/ioc-detection-engine
Attacker System
Kali Linux virtual machine
Used to generate SSH authentication activity against the Ubuntu system
Ubuntu IP Address During Testing
192.168.20.27
Attacker IP Address During Testing
192.168.20.18
Test Data Sources
Sample Authentication Log

File:

logs/sample-auth.log

Purpose:

Test predictable authentication scenarios
Verify alert formatting
Validate failed and successful login counting
Avoid dependence on large real-world logs
Real Authentication Log

Source:

/var/log/auth.log

Copied into:

logs/real-auth.log

Commands used:

sudo cp /var/log/auth.log logs/real-auth.log
sudo chown ubuntu:ubuntu logs/real-auth.log

Purpose:

Validate the engine against genuine Ubuntu authentication records
Analyse previous SSH login attempts
Confirm the parser works with larger datasets
Test Scenario 1 — IOC Match with Failed Login
Input

A source IP listed in:

data/iocs.json

was included in a failed SSH authentication event.

Example:

Failed password for admin from 45.141.215.90 port 2222 ssh2
Expected Result

The engine should:

Identify the IP as an IOC match
Count the failed login
Generate an alert
Assign a severity
Map the event to T1110
Save the alert to CSV
Observed Result

The engine generated an alert with:

IP: 45.141.215.90
Detection Type: IOC Match - SSH Brute Force
Severity: High
MITRE Technique: T1110 - Brute Force
Status: Open
Result
PASS
Test Scenario 2 — Multiple Failed Login Attempts
Input

Three failed login attempts were generated from:

192.168.56.101

The attempts targeted multiple usernames:

root
admin
test
Expected Result

The engine should:

Group events by source IP
Count all failed attempts
Avoid creating an unrelated alert for every individual line
Generate one consolidated alert with supporting evidence
Observed Result

The engine generated one alert showing:

IP: 192.168.56.101
Attempts: 3
Severity: High
MITRE: T1110 - Brute Force

The alert included all related evidence logs.

Result
PASS
Test Scenario 3 — Brute Force Followed by Successful Login
Input

The test log contained:

Multiple failed SSH login attempts
A later successful login
The same source IP for both failed and successful activity

Example source IP:

192.168.56.101
Expected Result

The engine should classify this as a possible compromise rather than a normal failed-login event.

Observed Result

The engine generated:

Type: Brute Force → Successful Login
Severity: CRITICAL
Failed Attempts: 3
Successful Logins: 1

MITRE ATT&CK mappings:

T1110 - Brute Force
T1078 - Valid Accounts
Result
PASS
Test Scenario 4 — Real SSH Activity
Test Procedure

An SSH connection was attempted from the Kali Linux VM against the Ubuntu VM.

The activity included:

Invalid username attempts
Repeated failed passwords
Connection termination
Successful login events from previous testing

Example log activity:

Invalid user fakeuser from 192.168.20.18
Failed password for invalid user fakeuser from 192.168.20.18
Connection closed by invalid user fakeuser
Expected Result

The engine should:

Parse the real authentication log
Identify the source IP
Count failures and successes
Match the source IP against the IOC feed
Generate a consolidated alert
Observed Result

The engine detected:

IP: 192.168.20.18
Failed Attempts: 65
Successful Logins: 17
Severity: CRITICAL
Type: Brute Force → Successful Login
Result
PASS
Test Scenario 5 — CSV Alert Generation
Expected Result

Each alert should be written to:

alerts/alerts.csv

The output should include:

Alert ID
Timestamp
IP address
Detection type
Severity
MITRE ATT&CK technique
Status
Recommended action
Evidence
Observed Result

The engine successfully created and updated:

alerts/alerts.csv

A reusable example was copied to:

alerts/sample-alerts.csv
Result
PASS
Test Scenario 6 — Evidence Limiting
Problem

When processing the full real authentication log, one IP produced hundreds of related log entries.

This made terminal output difficult to read.

Improvement Applied

The engine was updated to display only the most recent evidence entries while reporting how many additional logs were hidden.

Example:

--- Evidence (last 5) ---
... (226 more logs hidden)
Result
PASS
Known Testing Limitations
The current IOC feed is manually maintained
The engine processes stored logs rather than continuously streaming events
The current logic counts events across the full log file rather than a strict time window
Repeated historical events may increase totals
Real external threat intelligence enrichment has not yet been integrated
Some successful logins may be legitimate lab activity
No automated allowlist validation is currently applied
Automatic response actions must be tested carefully to avoid blocking trusted systems
Overall Test Result

The IOC Detection Engine successfully demonstrated:

IOC matching
SSH log parsing
Failed-login counting
Successful-login counting
Brute-force detection
Compromise-pattern detection
Severity classification
MITRE ATT&CK mapping
Evidence collection
CSV alert generation

Overall status:

CORE ENGINE TESTING COMPLETED
