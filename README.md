# IOC Detection Engine (SSH Log Analysis)

## What this project does

This project reads system login logs and identifies suspicious activity.

It focuses on detecting:
- Multiple failed login attempts (possible brute force attack)
- Successful logins after repeated failures (possible account compromise)

The system compares login activity with a list of known suspicious IP addresses and generates alerts.

---

## Why this matters

When attackers try to break into a system, they often:
1. Try many passwords (brute force)
2. Eventually succeed
3. Gain access to an account

This project detects that pattern and raises an alert.

---

## How it works (simple explanation)

1. The system reads login logs (SSH logs)
2. It extracts IP addresses from those logs
3. It compares those IPs with a known suspicious list (IOC list)
4. It counts:
   - Failed login attempts
   - Successful logins
5. Based on the behaviour, it classifies the activity:
   - Normal failure
   - Brute force attack
   - Brute force followed by successful login
6. It generates a clean alert summary

---

## Project structure

ioc-detection-engine/
│
├── src/
│ └── main.py # Main detection script
│
├── data/
│ └── iocs.json # List of suspicious IP addresses
│
├── logs/
│ ├── sample-auth.log # Sample log file (for demo)
│ └── real-auth.log # Real system logs (not uploaded to GitHub)
│
├── alerts/
│ ├── alerts.csv # Generated alerts
│ └── sample-alerts.csv # Example output
│
├── .gitignore
└── README.md


## How to run (simple steps)

### 1. Clone the repository

```bash
git clone <your-repo-link>
cd ioc-detection-engine

### 2. Run the script
python3 src/main.py

###Example output
🚨 ALERT #1
IP: 192.168.56.101
Failed Attempts: 3
Successful Logins: 1
Severity: CRITICAL
Type: Brute Force → Successful Login
-------------------------
This means:

The same IP tried multiple failed logins
Then successfully logged in
This is considered a high-risk event

--------------------------
Input and Output
Input:
SSH log file (sample-auth.log)
IOC list (iocs.json)
Output:
Alert summary in terminal
Detailed alert file (alerts.csv)
---------------------------------

Key features
Detects brute force login attempts
Identifies successful login after failures
Groups activity by IP address
Handles repeated log messages correctly
Provides clear, readable alerts
Saves results to CSV for analysis

------------------------------------

Notes
This project uses a sample log file for demonstration
Real system logs are not uploaded for privacy and security reasons
The logic can be extended to real-time monitoring systems
-----------------------------------------

Future improvements (optional ideas)
Real-time log monitoring
Integration with threat intelligence feeds (MISP)
Automatic IP blocking
Dashboard for visualization

----------------------------------------------------

Summary

This project demonstrates how suspicious login activity can be detected using simple logic applied to system logs.

It simulates how security teams identify and respond to potential attacks.
