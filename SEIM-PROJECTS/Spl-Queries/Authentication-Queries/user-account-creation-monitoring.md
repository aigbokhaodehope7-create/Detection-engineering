# Detection 011 – Windows User Account Creation Monitoring

## 1. Overview

Windows Security Event ID 4720 is generated when a user account is created.

Unauthorized account creation may indicate:
- Attacker persistence.
- Unauthorized administrative activity.
- Privilege escalation preparation.
- Compromised administrator credentials.

## 2. Objective

Detect newly created user accounts and identify who created them, where the event occurred, and whether the activity was authorized.

## 3. Event Information

| Field | Description |
|---|---|
| Event ID | 4720 |
| Event Name | A user account was created |
| Log Source | Windows Security |
| Systems | Windows endpoints and Domain Controllers |
| Severity | Context-dependent |

## 4. Detection Query – Identify New Accounts

```spl
index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4720
| table _time host SubjectUserName TargetUserName TargetDomainName
| sort - _time
