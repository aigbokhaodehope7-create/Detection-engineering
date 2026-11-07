# Detection 007 – Explicit Credential Usage

## 1. Overview

Windows Security Event ID 4648 is generated when a process attempts to log on using explicitly specified credentials.

This can occur during legitimate administrative activity or suspicious attempts to access another account.

## 2. Objective

Identify explicit credential usage and investigate unusual accounts, processes, and target systems.

## 3. Event Information

| Field | Description |
|---|---|
| Event ID | 4648 |
| Event Name | A logon was attempted using explicit credentials |
| Log Source | Windows Security |
| Data Source | Windows endpoint or server |
| Severity | Context-dependent |

## 4. Detection Query – Identify Explicit Credential Usage

```spl
index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4648
| table _time host SubjectUserName TargetUserName ProcessName
        TargetServerName IpAddress
| sort - _time
