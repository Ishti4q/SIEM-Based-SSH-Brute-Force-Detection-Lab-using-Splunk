# SIEM-Based SSH Brute-Force Detection Lab (Splunk)

## Overview
This project demonstrates a Security Information and Event Management (SIEM) implementation using Splunk to detect and analyze SSH brute-force attacks in a controlled lab environment. The goal was to simulate real-world attack behavior, ingest authentication logs, and build detection, alerting, and visualization capabilities similar to a SOC workflow.

---

## Objectives
- Ingest and analyze Linux authentication logs in Splunk  
- Simulate SSH brute-force attack activity  
- Develop SPL queries for threat detection  
- Configure automated alerts for suspicious behavior  
- Build a SOC-style dashboard for security monitoring  

---

## Environment
- Splunk Enterprise  
- Ubuntu Linux  
- OpenSSH Server  
- Authentication logs (`/var/log/auth.log`)  

---

## Implementation

### Log Ingestion
Linux SSH authentication logs were collected and indexed into Splunk for centralized analysis.

### Attack Simulation
Brute-force behavior was simulated by generating multiple failed SSH login attempts against a local test user account.

### Detection Logic
Custom SPL queries were created to:
- Identify failed SSH login attempts  
- Extract username and source IP address  
- Detect repeated authentication failures using thresholds  

Example query:
```spl
index=* "Failed password"
| rex "Failed password for (?<user>\w+) from (?<ip>\d+\.\d+\.\d+\.\d+)"
| stats count by user, ip
| where count > 3
```

### Alerting

A scheduled Splunk alert was configured to trigger when failed login attempts exceeded defined thresholds. The alert simulates SOC-style detection and notification workflows.

### Dashboard

A SOC-style dashboard was created to provide visibility into:

-Failed login trends over time
-Top source IP addresses
-Total authentication failures
-Raw authentication event logs

### Challenges
-Splunk license and startup configuration issues
-Disk space limitations affecting indexing
-SSH service setup and connectivity problems
-Log ingestion troubleshooting

### Key Learnings
-SIEM architecture and Splunk fundamentals
-Log ingestion and normalization
-SPL query development for threat detection
-Security monitoring and alerting workflows
-SOC-style dashboard design and analysis

### Conclusion

This project demonstrates a complete SIEM workflow from log ingestion and attack simulation to detection, alerting, and visualization, reflecting core SOC analyst skills.

