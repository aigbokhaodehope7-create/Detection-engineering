# Detection 003: Password Spraying Detection

## 1. Detection Objective

Identify possible password spraying activity by investigating failed authentication attempts against multiple user accounts.

The objective is to identify suspicious authentication patterns originating from a common source.

## 2. Attack Description

Password spraying is a credential access technique in which an attacker attempts a small number of common passwords against multiple accounts.

Unlike traditional brute-force attacks, password spraying distributes attempts across several accounts to reduce the likelihood of account lockout.

## 3. Data Source

- Platform: Windows
- Log Source: Windows Security Event Logs
- Event ID: 4625
- SIEM: Wazuh
- Query Language: DQL

## 4. DQL Query A: Identify Failed Logons

```text
data.win.system.eventID: "4625"
