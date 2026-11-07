# Wazuh DQL Detection Queries

## Overview

This directory contains practical Wazuh Dashboard Query Language (DQL) searches for security monitoring, threat hunting and SOC investigations.

DQL helps analysts search and filter security events and alerts stored in Wazuh.

**Important:** DQL is used to search indexed security data. Wazuh XML rules are responsible for generating alerts.

## Query Categories

1. Authentication and Failed Logins
2. Windows Security Events
3. Linux Security Events
4. Privilege Escalation
5. Malware Investigation
6. Network Activity
7. Suspicious Process Execution
8. User Account Monitoring
9. Persistence Detection
10. Threat Hunting

## Documentation

Each query will include:

- Query name and objective
- DQL search query
- Explanation of the fields
- Expected results
- Relevant Event IDs or Wazuh rule IDs
- False-positive considerations
- Investigation steps
- MITRE ATT&CK mapping

## Author

Hope - HopeLabs Detection Engineering
