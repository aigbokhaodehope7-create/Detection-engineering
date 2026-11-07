# Splunk Authentication Detection Queries

## Overview

This directory contains SPL detections for monitoring authentication activities across Windows environments.

The queries help SOC analysts investigate failed logons, suspicious login patterns, brute-force attacks and possible account compromise.

## Detection Categories

1. Windows Failed Logons
2. Successful Logins
3. Brute-Force Attacks
4. Password Spraying
5. Successful Login After Multiple Failures
6. Suspicious Source IP Addresses
7. Privileged Account Authentication
8. Logon Outside Business Hours
9. Account Lockout Monitoring
10. Authentication Anomalies

## Data Sources

- Windows Security Event Logs
- Windows Event ID 4624
- Windows Event ID 4625
- Windows Event ID 4648
- Windows Event ID 4672
- Windows Event ID 4740
- Sysmon where relevant

## Documentation Standards

Each detection will include:

- Detection objective
- SPL query
- Required indexes and sourcetypes
- Field explanations
- Expected output
- False-positive considerations
- Investigation procedure
- MITRE ATT&CK mapping
- Validation and evidence

## Author

Hope - HopeLabs Detection Engineering
