# Lessons Learned

## Technical Lessons

### 1. Detection quality depends on context

A failed SSH login alone does not always indicate a serious attack.

The risk becomes higher when additional context is present, such as:

- repeated failed attempts
- multiple usernames targeted
- a later successful login
- a known malicious source IP
- suspicious activity after authentication

This showed that effective detection requires correlation rather than checking isolated log lines.

---

### 2. IOC matching alone is not enough

A source IP appearing in an IOC feed can be useful, but it should not automatically be treated as a confirmed compromise.

IOC information can be:

- outdated
- incomplete
- inaccurate
- reused by legitimate services
- missing context

The engine therefore combines IOC matching with observed authentication behaviour.

---

### 3. Grouping events improves alert quality

The first versions of the engine created separate alerts for individual log lines.

This produced duplicate and noisy output.

The engine was improved to group activity by source IP and generate a consolidated alert containing:

- failed-login count
- successful-login count
- classification
- severity
- supporting evidence

This produced clearer and more useful alerts.

---

### 4. Failed logins followed by success require higher severity

Repeated failures followed by a successful login may indicate that an attacker discovered valid credentials.

This pattern was classified as Critical and mapped to:

- T1110 - Brute Force
- T1078 - Valid Accounts

This was more meaningful than treating every failed login as the same level of risk.

---

### 5. Large logs require evidence filtering

Real authentication logs contained hundreds of related events.

Displaying every matching line made the terminal output difficult to review.

The engine was changed to display only the latest evidence entries and show how many additional records were hidden.

This improved readability without discarding the underlying evidence stored in the source log.

---

### 6. Sample data and real data serve different purposes

Sample logs were useful for:

- predictable testing
- validating specific scenarios
- checking output formatting
- reproducing results

Real logs were useful for:

- testing parser reliability
- identifying unexpected log formats
- validating behaviour against genuine system activity
- exposing performance and noise issues

Both forms of testing were necessary.

---

### 7. Automatic blocking introduces operational risk

Blocking a suspicious IP using `iptables` can reduce exposure, but automated response must be carefully controlled.

Potential risks include:

- blocking an administrator
- blocking a shared IP address
- disrupting legitimate services
- locking out the analyst from the lab
- responding to a false positive

Future automated response should include:

- allowlisting
- confidence thresholds
- approval options
- rollback capability
- detailed audit logging

---

### 8. Historical log data can distort counts

The current engine processes all matching events in the selected file.

Because `real-auth.log` contains older activity, the failed and successful login totals may include events from different testing periods.

A production-quality version should use:

- a defined time window
- event timestamps
- session correlation
- state tracking
- incremental log processing

---

### 9. Documentation is part of the project

The project originally focused mainly on code and terminal output.

Reconstructing the work later showed the importance of maintaining:

- architecture notes
- setup instructions
- testing evidence
- lessons learned
- screenshots
- Git history
- a clear roadmap

Good documentation makes the project easier to maintain, explain and present in interviews.

---

## Troubleshooting Lessons

### Git repository initialisation

The command:

```bash
git add README.md

initially failed because the directory was not yet a Git repository.

The issue was fixed using:

git init
git add .
git commit -m "Initial commit - IOC Detection Engine"
Git author identity

The first commit used the automatically generated Ubuntu VM identity.

The correct Git identity was then configured:

git config --global user.name "Kaartheeswaran Ravichandran"
git config --global user.email "kaartheeravi@gmail.com"

The commit author was corrected using:

git commit --amend --reset-author
Shell command versus Python variable

The following line was accidentally entered directly into the shell:

LOG_FILE = "logs/real-auth.log"

The shell returned:

LOG_FILE: command not found

This happened because the line was Python code and needed to be placed inside:

src/main.py

This reinforced the difference between:

shell commands
Python statements
configuration values
Permission handling for auth.log

The system authentication log is restricted.

To use it safely in the project, it was copied and ownership was changed:

sudo cp /var/log/auth.log logs/real-auth.log
sudo chown ubuntu:ubuntu logs/real-auth.log

This allowed the detection engine to read the copied file without running the entire Python program as root.

Security Lessons
Detection does not equal confirmation

An alert indicates suspicious activity, not guaranteed compromise.

Analyst validation is still required.

Severity should be evidence-based

Severity should consider:

number of attempts
successful authentication
IOC confidence
user targeted
timing
post-login activity
whether the source is trusted
Response should be proportional

Possible actions range from:

monitoring
rate limiting
password reset
account disablement
IP blocking
forensic review

The action should match the confidence and impact of the alert.

Future Improvements Identified
Add time-window-based correlation
Add trusted-IP allowlisting
Add continuous log monitoring
Add deduplication across repeated runs
Add external IOC enrichment
Add MISP integration
Add STIX output
Add structured JSON alerts
Add unit tests
Add configuration files
Add command-line arguments
Add dashboard visualisation
Add alert lifecycle tracking
Add safe automated response controls
Interview Summary

The most important lesson from this project was that useful security detection requires more than matching a single indicator.

The project evolved from simple IOC matching into behaviour-based correlation that considers failed attempts, successful logins, severity, MITRE ATT&CK mapping, evidence and response recommendations.

It also demonstrated the importance of reducing alert noise, validating against real logs and carefully controlling automated response actions.
