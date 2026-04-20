# SIEM-Based SSH Brute-Force Detection Lab (Splunk)

## Overview

This project demonstrates a Security Information and Event Management (SIEM) implementation using Splunk Enterprise to detect and analyze SSH brute-force attacks in a controlled lab environment. The goal was to simulate real-world attack behavior, ingest Linux authentication logs, and build detection, alerting, and visualization capabilities that reflect a real SOC analyst workflow.

The project was built in two phases. The first phase established the core pipeline: log ingestion, basic detection, scheduled alerting, and a 4-panel dashboard. The second phase upgraded the simulation volume, rewrote the detection query to use time-based logic, switched to real-time alerting, and added a new dashboard panel showing attack rate per minute. The upgraded real-time alert fired 4 High-severity alerts during live testing.

---

## Environment

| Component     | Details                               |
| ------------- | ------------------------------------- |
| OS            | Ubuntu Linux (ishtiaq-Nitro-AN515-58) |
| SIEM Platform | Splunk Enterprise                     |
| SSH Server    | OpenSSH Server (sshd)                 |
| Log Source    | /var/log/auth.log                     |
| Sourcetype    | linux_secure                          |
| Attack Target | victim@127.0.0.1 (localhost)          |

---

## Objectives

* Simulate a realistic SSH brute-force attack in a safe, isolated lab environment
* Collect and ingest Linux authentication logs into Splunk Enterprise for analysis
* Build SPL detection logic starting with count-based thresholds, then upgrading to time-based detection
* Configure automated alerting, upgraded from scheduled to real-time
* Design and deploy a SOC monitoring dashboard with multiple panels
* Demonstrate the full detect, alert, and visualize SIEM workflow end-to-end

---

## Implementation

### Attack Simulation

SSH brute-force behavior was simulated in two stages.

Phase 1 involved manually running repeated SSH login attempts with incorrect passwords against a local victim account, producing 3 failed login events in auth.log.

Phase 2 replaced manual attempts with a bash loop generating 20 rapid connection attempts in quick succession, producing 35+ failed authentication events within a single minute.

```bash
for i in {1..20}; do ssh victim@127.0.0.1; done
```

Log entries were verified using:

```bash
grep "Failed password" /var/log/auth.log | tail -20
```

---

### Log Ingestion

Splunk Enterprise was configured to monitor /var/log/auth.log as a live data input with sourcetype linux_secure. Events were indexed continuously as they were written to disk.

Ingestion was verified using:

```spl
index=* "Failed password"
```

After the Phase 2 simulation, 40 events were confirmed indexed in Splunk.

---

### Detection Logic

#### Phase 1: Count-Based Detection

```spl
index=* "Failed password"
| rex "Failed password for (?<user>\w+) from (?<ip>\d+\.\d+\.\d+\.\d+)"
| stats count by user, ip
| where count > 3
```

#### Phase 2: Time-Based Detection (Upgraded)

```spl
index=* "Failed password"
| rex "Failed password for (?<user>\w+) from (?<ip>\d+\.\d+\.\d+\.\d+)"
| bin _time span=1m
| stats count by _time, ip, user
| where count > 5
```

The upgraded query buckets events into 1-minute windows and flags when more than 5 failures come from the same IP and user within a single minute. During testing this returned: IP 127.0.0.1, user victim, count 35, all within the 11:53 AM minute bucket.

---

### Full SPL Query Reference

```spl
# 1. Basic log search
index=* "Failed password"

# 2. Extract user and IP
index=* "Failed password"
| rex "Failed password for (?<user>\w+) from (?<ip>\d+\.\d+\.\d+\.\d+)"

# 3. Original brute-force detection (count threshold)
index=* "Failed password"
| rex "Failed password for (?<user>\w+) from (?<ip>\d+\.\d+\.\d+\.\d+)"
| stats count by user, ip
| where count > 3

# 4. Upgraded brute-force detection (time-based)
index=* "Failed password"
| rex "Failed password for (?<user>\w+) from (?<ip>\d+\.\d+\.\d+\.\d+)"
| bin _time span=1m
| stats count by _time, ip, user
| where count > 5

# 5. Failed login trend over time
index=* "Failed password"
| timechart count

# 6. Top attacker IPs
index=* "Failed password"
| rex "from (?<ip>\d+\.\d+\.\d+\.\d+)"
| stats count by ip
| sort - count

# 7. Total failed logins
index=* "Failed password"
| stats count

# 8. Raw logs
index=* sourcetype=linux_secure
```

---

### Alerting

| Parameter  | Phase 1                         | Phase 2                                |
| ---------- | ------------------------------- | -------------------------------------- |
| Alert Name | Brute Force SSH Login Detection | Brute Force SSH - Time Based Detection |
| Alert Type | Scheduled (hourly)              | Real-time                              |
| Trigger    | Number of results > 3           | Per-Result                             |
| Severity   | High                            | High                                   |
| Action     | Add to Triggered Alerts         | Add to Triggered Alerts                |

During live testing the Phase 2 alert fired 4 times within seconds of each other, confirming real-time detection was working correctly.

---

### Dashboard

| Panel                           | Description                                                                  |
| ------------------------------- | ---------------------------------------------------------------------------- |
| Failed Login Trend Over Time    | Time-stamped table of raw failed login events                                |
| Top Source IP Addresses         | Time-series line chart showing attempt count over the monitoring period      |
| Top Attacker IPs                | Bar chart ranking IPs by number of failed login attempts                     |
| Total Failed Logins             | Aggregate count of all failed login events                                   |
| Brute Force Attempts Per Minute | Line chart showing attack rate per minute with clear spike at time of attack |

---

### Challenges and Fixes

| Challenge                              | Fix                                                                                   |
| -------------------------------------- | ------------------------------------------------------------------------------------- |
| SSH service not running                | Installed and started OpenSSH with apt install openssh-server and systemctl start ssh |
| Splunk disk space warnings             | Cleared temp files to free up space for indexing                                      |
| Indexing time range issues             | Adjusted search time range to Last 24 hours                                           |
| Host key verification prompt           | Accepted fingerprint on first connection                                              |
| Low event count from manual simulation | Replaced with bash loop generating 35+ events per minute                              |
| Scheduled alert not reactive enough    | Switched to real-time alert with Per-Result trigger                                   |

---

## What I Learned

* How a SIEM transforms raw log lines into actionable alerts in real time
* Writing SPL from scratch including regex extraction, time bucketing, and threshold filtering
* Why time-based detection is more realistic than simple count-based detection
* The practical difference between scheduled and real-time alerting in a SOC context
* How small configuration details like search time ranges can break an otherwise correct query

---

## What Comes Next

* Set up a two-VM environment with a dedicated attacker and victim machine
* Use Hydra to automate the attack with varied usernames and passwords
* Add geolocation lookup using the iplocation SPL command and a map panel
* Add detection for successful logins that follow a series of failures
* Build an automated response layer using ufw to block attacker IPs when the alert fires

---

## Tools Used

* Splunk Enterprise
* Ubuntu Linux
* OpenSSH Server
* SPL (Search Processing Language)
* Bash



