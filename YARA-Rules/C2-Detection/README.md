
Command and Control (C2) Detection

1. Overview

This directory contains YARA rules designed to identify file-based indicators associated with Command and Control (C2) activity.

Command and Control is a communication mechanism attackers use to remotely communicate with compromised systems.

Through C2 infrastructure, attackers may issue commands, receive stolen information, download additional malware or maintain access to compromised environments.

2. Detection Objectives

- Understand Command and Control infrastructure.
- Identify suspicious communication-related strings.
- Recognise potential C2 indicators embedded in files.
- Identify suspicious URLs and domain references.
- Support threat hunting and malware analysis.

3. What We Will Detect

- Suspicious URLs embedded in files.
- Known malicious domain indicators.
- Suspicious IP address patterns.
- C2-related configuration strings.
- Recognisable malware communication patterns.
- Potential beaconing-related indicators stored in files.

4. Tools Required

- YARA
- VirusTotal
- AbuseIPDB
- URLScan.io
- Wireshark
- Suricata
- Wazuh
- Splunk

5. SOC Analyst Investigation

When a suspicious C2 indicator is identified:

1. Extract the suspicious indicator.
2. Identify the associated file or process.
3. Calculate the file's SHA256 hash where applicable.
4. Check the indicator using approved threat intelligence sources.
5. Review network connections and DNS activity.
6. Correlate findings with SIEM alerts.
7. Map relevant behaviour to MITRE ATT&CK.
8. Document findings and recommend containment.

6. Important Detection Note

YARA detects patterns in files and other supported data. It does not independently monitor live network traffic.

Tools such as Suricata, Wireshark and SIEM platforms are more appropriate for investigating live network communications and C2 activity.

7. Expected Learning Outcomes

Develop practical skills in identifying C2-related indicators, investigating suspicious files and correlating malware findings with network security events.

8. Safety

All testing must be performed in controlled, authorised laboratory environments. Use harmless test indicators and never connect to malicious C2 infrastructure.
