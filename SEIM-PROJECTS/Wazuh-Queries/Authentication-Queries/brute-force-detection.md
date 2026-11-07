# Detection 004: Brute-Force Attack Investigation

## 1. Detection Objective

Identify repeated failed authentication attempts against a single user account that may indicate a brute-force attack.

## 2. Attack Description

A brute-force attack involves repeatedly attempting different passwords against a targeted account until valid credentials are discovered.

Attackers may use automated tools to generate numerous authentication attempts.

## 3. Data Source

- Operating System: Windows
- Log Source: Windows Security Event Logs
- Event ID: 4625
- SIEM: Wazuh
- Query Language: DQL

## 4. DQL Query A: Identify Failed Authentication

```text
data.win.system.eventID: "4625"
