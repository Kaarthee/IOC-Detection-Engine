# Threat Intelligence and Detection Platform

## Project Overview

This project is a modular cybersecurity platform designed to connect threat intelligence, log analysis, detection engineering, and automated response.

The long-term objective is to create a complete pipeline that can:

1. Capture suspicious activity
2. Extract indicators of compromise
3. Enrich indicators using threat intelligence
4. Detect related activity in system logs
5. Generate alerts and response recommendations
6. Produce detection content for security tools

---

## Current Project Status

### Completed: SSH Abuse Detection Lab

A Python-based SSH monitoring and detection system was developed on Ubuntu.

Key capabilities included:

- SSH authentication log monitoring
- Brute-force detection
- Successful login after repeated failures
- Behaviour-based severity scoring
- MITRE ATT&CK mapping
- Automatic IP blocking using iptables
- CSV and JSON alert generation
- Investigation timeline creation
- Detection of suspicious sessions and possible tunnelling behaviour

Relevant MITRE ATT&CK techniques:

- T1110 - Brute Force
- T1078 - Valid Accounts
- T1021.004 - SSH Remote Services
- T1572 - Protocol Tunnelling

---

### Completed: WireGuard VPN Lab

A secure remote-access VPN lab was configured using WireGuard.

Key capabilities included:

- Linux WireGuard server
- Windows client configuration
- Public and private key authentication
- IP forwarding
- NAT and routing
- Firewall configuration
- Connectivity and traffic validation

---

### Completed: IOC Detection Engine

The IOC Detection Engine reads SSH authentication logs and compares observed IP addresses against a local IOC feed.

Key capabilities:

- Reads IOC data from JSON
- Reads SSH authentication logs
- Detects malicious IP matches
- Counts failed and successful login attempts
- Detects brute force followed by successful authentication
- Assigns severity levels
- Maps activity to MITRE ATT&CK
- Generates CSV alerts
- Provides evidence logs and response recommendations

Current data sources:

- Local IOC JSON feed
- Sample SSH authentication logs
- Real Ubuntu auth.log data

Current outputs:

- Terminal alerts
- CSV alert records
- MITRE ATT&CK mappings
- Recommended response actions

---

## Current Repository Structure

```text
ioc-detection-engine/
├── alerts/
│   ├── alerts.csv
│   └── sample-alerts.csv
├── data/
│   └── iocs.json
├── docs/
│   ├── architecture.md
│   ├── lessons-learned.md
│   ├── setup-guide.md
│   ├── testing.md
│   └── screenshots/
├── logs/
│   ├── auth.log
│   ├── real-auth.log
│   └── sample-auth.log
├── notes/
│   ├── misp-notes.md
│   ├── mitre-notes.md
│   └── stix-taxii-notes.md
├── src/
│   └── main.py
├── .gitignore
├── PROJECT_MASTER.md
└── README.md

Threat Intelligence Foundation

Practical and theoretical topics already explored:

MISP
STIX
TAXII
ORKL
OpenCTI
MITRE ATT&CK
Diamond Model
Cyber Kill Chain
Pyramid of Pain
IOC enrichment
Threat actors
Campaigns
Malware
Galaxies
Taxonomies
MISP events and attributes
Planned Pipeline
Honeypot
   ↓
IOC Extraction
   ↓
Threat Intelligence Enrichment
   ↓
IOC Detection Engine
   ↓
Detection and Response Automation
   ↓
Dashboard and Analyst Reporting
Planned Phases
Phase 1 - Intelligent Honeypot

Planned purpose:

Capture attacker IP addresses
Record attempted usernames and passwords
Record commands and sessions
Extract URLs and possible malware indicators
Produce structured attack data

Potential technology:

Cowrie SSH and Telnet honeypot

Status:

Planned
Installation not yet confirmed
Phase 2 - IOC Extraction and Normalisation

Planned purpose:

Extract IP addresses
Extract domains and URLs
Extract file hashes
Remove duplicates
Record first-seen and last-seen timestamps
Convert raw observations into structured indicators

Status:

Planned
Phase 3 - Threat Intelligence Enrichment

Planned integrations:

MISP
ORKL
AbuseIPDB
VirusTotal
AlienVault OTX

Planned output:

Threat score
Confidence score
ASN and location information
Known campaigns
Malware associations
MITRE ATT&CK mappings

Status:

Planned
Phase 4 - Detection Automation

Planned outputs:

Sigma rules
Splunk searches
Microsoft Sentinel KQL
Wazuh rules
Firewall blocklists
Automated response recommendations

Status:

Planned
Phase 5 - Dashboard and Reporting

Planned capabilities:

Attack timeline
Alert summary
Threat score
IOC history
MITRE ATT&CK visualisation
Analyst notes
Incident summaries

Status:

Planned
Immediate Next Step

The next step is to verify the saved virtual machines and determine whether a Cowrie honeypot was previously installed.

No new installation should be performed until the current VM state is inspected.

Documentation Rules

For every completed phase, record:

Objective
Architecture
Tools used
Setup steps
Testing method
Screenshots
Sample output
Problems encountered
Solutions applied
Security limitations
Future improvements
Resume-ready summary
Interview explanation
Project Goal

The final platform should demonstrate the complete security workflow:

Attack Observed
      ↓
Indicator Extracted
      ↓
Threat Enriched
      ↓
Activity Detected
      ↓
Response Recommended
