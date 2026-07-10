# Setup Guide

## Purpose

This guide explains how to set up and run the IOC Detection Engine in a local Ubuntu environment.

---

## Prerequisites

Required:

- Ubuntu Linux
- Python 3
- Git
- Basic terminal access

Check Python:

```bash
python3 --version

Check Git:

git --version
Project Location

Current project path:

/home/ubuntu/ioc-detection-engine

Move into the project:

cd ~/ioc-detection-engine

Confirm:

pwd

Expected output:

/home/ubuntu/ioc-detection-engine
Repository Structure
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
Configure the IOC Feed

Open:

nano data/iocs.json

The file should contain suspicious or malicious IP addresses in valid JSON format.

Example:

{
  "malicious_ips": [
    "192.168.56.101",
    "45.141.215.90",
    "192.168.20.18"
  ]
}

Save using:

Ctrl + O
Enter
Ctrl + X
Configure the Log Source

The engine can use either sample logs or a copied real authentication log.

Sample Log

Recommended for predictable testing:

logs/sample-auth.log
Real Ubuntu Log

System source:

/var/log/auth.log

Copy it into the project:

sudo cp /var/log/auth.log logs/real-auth.log
sudo chown ubuntu:ubuntu logs/real-auth.log

Do not commit the real log to a public repository because it may contain:

usernames
IP addresses
timestamps
authentication records
system details
Select the Log File

Open the Python source:

nano src/main.py

Find the log file configuration.

Example for sample testing:

LOG_FILE = "logs/sample-auth.log"

Example for real-log testing:

LOG_FILE = "logs/real-auth.log"

Save the file before running.

Run the Detection Engine

From the project root:

python3 src/main.py

Expected startup output:

========== IOC Detection Engine ==========

The engine should then:

Load the IOC feed
Read the selected authentication log
Extract source IP addresses
Count failed and successful logins
Match observed IPs against the IOC feed
Classify suspicious behaviour
Display alerts
Write results to CSV
Review Alert Output

Terminal alerts appear during execution.

CSV output:

alerts/alerts.csv

View it using:

cat alerts/alerts.csv

For easier reading:

column -s, -t < alerts/alerts.csv | less -S

Exit less by pressing:

q
Test with Sample Data

Run:

python3 src/main.py

A successful sample test should detect:

repeated failed logins
an IOC match
failed logins followed by a successful login
severity classification
MITRE ATT&CK mappings

Expected classifications may include:

Login Failures
IOC Match - SSH Brute Force
Brute Force → Successful Login
Git Configuration

Configure the Git author:

git config --global user.name "Kaartheeswaran Ravichandran"
git config --global user.email "kaartheeravi@gmail.com"

Check:

git config --global user.name
git config --global user.email
Save Changes with Git

Check changed files:

git status

Stage changes:

git add .

Commit:

git commit -m "Add project documentation"

Review commit history:

git log --oneline
Security Precautions
Use the project only in an authorised lab environment
Do not expose the Ubuntu SSH service directly to the public internet
Do not publish genuine authentication logs
Do not commit credentials or API keys
Do not automatically block trusted IP addresses
Keep a recovery method available before testing firewall rules
Validate JSON before running the engine
Review alerts manually before taking response actions
Common Issues
Python file not found

Error:

python3: can't open file

Fix:

cd ~/ioc-detection-engine
python3 src/main.py
Log file not found

Check available files:

ls -l logs/

Confirm that the LOG_FILE value in src/main.py matches the actual filename.

Permission denied reading auth.log

Use a copied version:

sudo cp /var/log/auth.log logs/real-auth.log
sudo chown ubuntu:ubuntu logs/real-auth.log
Invalid JSON

Validate the IOC feed:

python3 -m json.tool data/iocs.json

A valid file will be printed in formatted JSON.

Git repository not initialised

Run:

git init
git add .
git commit -m "Initial commit - IOC Detection Engine"
Current Limitations
Static local IOC feed
Stored log-file processing
No live monitoring
No time-window correlation
No automatic MISP integration
No external enrichment
No dashboard
No automated rule generation

These will be addressed in later phases.
