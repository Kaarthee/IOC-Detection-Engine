# System Architecture

## Current IOC Detection Engine

The current implementation analyses SSH authentication logs and compares observed IP addresses against a local IOC feed.

```text
Local IOC Feed
data/iocs.json
      │
      ▼
Python Detection Engine
src/main.py
      │
      ├── Reads SSH logs
      ├── Extracts IP addresses
      ├── Counts failed logins
      ├── Counts successful logins
      ├── Matches IPs against IOC feed
      ├── Assigns severity
      └── Maps activity to MITRE ATT&CK
      │
      ▼
Alert Output
alerts/alerts.csv
Current Inputs
IOC Feed

File:

data/iocs.json

Purpose:

Stores IP addresses considered suspicious or malicious
Acts as the current threat intelligence source
Allows the engine to compare log activity against known indicators
Authentication Logs

Files:

logs/sample-auth.log
logs/auth.log
logs/real-auth.log

Purpose:

Provide SSH authentication events
Include failed login attempts
Include successful login events
Provide source IP addresses and usernames
Support testing with sample and real log data
Detection Logic

The engine performs the following steps:

Load indicators from the local JSON feed
Read the selected SSH authentication log
Extract source IP addresses
Group activity by IP address
Count failed authentication attempts
Count successful authentication attempts
Check whether the IP appears in the IOC feed
Classify the observed behaviour
Assign severity
Map the activity to MITRE ATT&CK
Generate an alert
Save the result to CSV
Current Detection Scenarios
IOC Match with Login Failures

Condition:

IP appears in the IOC feed
One or more failed SSH login attempts are present

Classification:

IOC Match - SSH Brute Force

Possible severity:

Medium or High

MITRE ATT&CK:

T1110 - Brute Force
Brute Force Followed by Successful Login

Condition:

Multiple failed login attempts occur
A successful login later occurs from the same IP

Classification:

Brute Force Followed by Successful Login

Severity:

Critical

MITRE ATT&CK:

T1110 - Brute Force
T1078 - Valid Accounts
Current Outputs

The engine produces:

Terminal alerts
CSV alert records
Severity ratings
MITRE ATT&CK mappings
Evidence logs
Recommended response actions

Main output file:

alerts/alerts.csv
Planned Extended Architecture
Cowrie Honeypot
      │
      ▼
Raw Attack Events
      │
      ▼
IOC Extraction and Normalisation
      │
      ├── IP addresses
      ├── Domains
      ├── URLs
      └── File hashes
      │
      ▼
Threat Intelligence Enrichment
      │
      ├── MISP
      ├── ORKL
      ├── AbuseIPDB
      ├── VirusTotal
      └── AlienVault OTX
      │
      ▼
IOC Detection Engine
      │
      ▼
Detection and Response Automation
      │
      ├── Sigma
      ├── Splunk
      ├── Sentinel KQL
      ├── Wazuh
      └── Firewall actions
      │
      ▼
Dashboard and Analyst Reporting
Security Boundaries

The current implementation is a lab-based prototype.

Current limitations:

Uses a local static IOC feed
Processes stored log files rather than continuous live ingestion
Does not yet validate external intelligence confidence
Does not yet deduplicate all repeated evidence
Does not yet push indicators automatically into MISP
Does not yet generate production-ready detection rules
Automatic blocking requires careful allowlisting to prevent accidental lockout
Design Goal

The architecture is intended to demonstrate the full operational security workflow:

Collection
   ↓
Intelligence
   ↓
Detection
   ↓
Alerting
   ↓
Response
