# IOC Detection Engine

A Python-based security detection project that analyses SSH authentication logs, correlates login behaviour with threat intelligence indicators, and generates structured security alerts.

The engine was developed in an isolated Ubuntu and Kali Linux lab environment to demonstrate practical detection engineering, log analysis, IOC correlation, MITRE ATT&CK mapping, and security alert generation.

---

## Project Overview

The IOC Detection Engine processes SSH authentication logs and identifies suspicious activity such as:

- repeated failed login attempts
- SSH brute-force behaviour
- successful authentication following multiple failures
- activity originating from known suspicious IP addresses
- potentially compromised accounts

Instead of generating one alert for every log entry, the engine groups related activity by source IP address and produces consolidated alerts containing severity, classification, evidence, and recommended investigation context.

---

## Detection Workflow

```text
SSH Authentication Logs
          |
          v
   Log Parsing Engine
          |
          v
Source IP Extraction
          |
          +----------------------+
          |                      |
          v                      v
Behaviour Analysis        IOC Feed Matching
          |                      |
          +----------+-----------+
                     |
                     v
              Alert Classification
                     |
                     v
          Terminal and CSV Output
```

The engine performs the following steps:

1. Reads SSH authentication logs
2. Extracts source IP addresses
3. Identifies failed and successful login events
4. Groups events by source IP
5. Compares observed IP addresses with a local IOC feed
6. Correlates repeated failures with later successful authentication
7. Assigns severity and attack classification
8. Maps relevant activity to MITRE ATT&CK
9. Writes structured alerts to CSV

---

## Key Features

- Python-based SSH log analysis
- IOC matching using a local JSON threat feed
- Event grouping by source IP address
- Failed and successful login counting
- SSH brute-force detection
- Detection of successful login following repeated failures
- Severity-based alert classification
- MITRE ATT&CK mapping
- Evidence preservation
- CSV alert generation
- Support for sample and real Ubuntu authentication logs
- Privacy controls through `.gitignore`

---

## Detection Scenarios

### Repeated Login Failures

Multiple failed authentication attempts from the same IP may indicate password guessing or brute-force activity.

### IOC Match

Observed IP addresses are compared with a local list of known suspicious indicators.

An IOC match provides additional threat context but is not treated as proof of compromise by itself.

### Brute Force Followed by Successful Login

When repeated failed attempts are followed by successful authentication from the same IP, the engine classifies the event as a critical security alert.

This pattern may indicate that valid credentials were discovered or compromised.

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection context |
|---|---|---|
| Brute Force | T1110 | Repeated failed SSH authentication attempts |
| Valid Accounts | T1078 | Successful authentication following suspicious failures |

---

## Project Structure

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
```

Real authentication logs and generated production alerts are excluded from Git tracking.

---

## Requirements

- Ubuntu or another Linux environment
- Python 3
- Git

No external Python packages are currently required.

Check Python:

```bash
python3 --version
```

---

## Running the Engine

Clone the repository:

```bash
git clone <repository-url>
cd ioc-detection-engine
```

Run the detection engine:

```bash
python3 src/main.py
```

Detailed setup instructions are available in:

```text
docs/setup-guide.md
```

---

## Example Alert

```text
ALERT #1

Source IP: 192.168.56.101
Failed Attempts: 3
Successful Logins: 1
Severity: CRITICAL
Classification: Brute Force → Successful Login
MITRE ATT&CK: T1110, T1078
```

This alert indicates that the same source IP generated repeated failed login attempts and later authenticated successfully.

---

## Inputs

### SSH Log File

The engine can analyse:

- controlled sample logs
- copied Ubuntu authentication logs
- simulated SSH attack activity

### IOC Feed

Suspicious source IP addresses are stored in:

```text
data/iocs.json
```

---

## Outputs

The engine produces:

- terminal alert summaries
- severity classification
- attack classification
- supporting log evidence
- MITRE ATT&CK mapping
- structured CSV alerts

Example output:

```text
alerts/sample-alerts.csv
```

The generated `alerts/alerts.csv` file is ignored by Git.

---

## Testing

The engine was tested using both controlled sample logs and genuine Ubuntu authentication logs from an isolated lab.

Validated scenarios include:

- IOC-matched failed login
- repeated authentication failures
- brute force followed by successful login
- real SSH activity from a Kali Linux system
- CSV alert generation
- evidence output limiting

Full testing documentation is available in:

```text
docs/testing.md
```

---

## Security and Privacy

This project is intended for authorised lab and defensive security use.

Security measures include:

- excluding real authentication logs from Git
- excluding generated alert files
- avoiding credentials and API keys
- using controlled sample evidence for demonstrations
- separating detection from automated response
- documenting the risk of false positives

---

## Current Limitations

- static local IOC feed
- stored log-file processing
- no continuous real-time monitoring
- no time-window-based event correlation
- no automatic MISP integration
- no external threat intelligence enrichment
- no dashboard
- no automated response controls

---

## Planned Improvements

- real-time log monitoring
- time-window correlation
- MISP integration
- STIX and TAXII support
- external IOC enrichment
- JSON alert output
- command-line configuration
- unit testing
- alert deduplication
- trusted-IP allowlisting
- dashboard visualisation
- controlled automated response

---

## Skills Demonstrated

- Python
- Linux
- SSH log analysis
- detection engineering
- threat intelligence
- IOC correlation
- MITRE ATT&CK
- incident triage
- CSV and JSON handling
- Git version control
- security documentation
- defensive security testing

---

## Documentation

Additional technical documentation is available in:

- `PROJECT_MASTER.md`
- `docs/architecture.md`
- `docs/setup-guide.md`
- `docs/testing.md`
- `docs/lessons-learned.md`

---

## Author

**Kaartheeswaran Ravichandran**

Master of Cybersecurity student focused on security operations, detection engineering, threat intelligence, and incident response.

