# Detection 006 – Windows Account Lockout Monitoring

## 1. Overview

This detection monitors Windows Security Event ID 4740 to identify user accounts that have been locked out.

Account lockouts may result from:
- Repeated incorrect password attempts.
- Brute-force attacks.
- Password spraying.
- Stale credentials on applications or devices.
- Misconfigured services using outdated passwords.

## 2. Objective

Identify locked-out accounts, investigate the source of the lockout, and determine whether the activity is malicious or legitimate.

## 3. Windows Event Information

| Field | Description |
|---|---|
| Event ID | 4740 |
| Event Name | A user account was locked out |
| Log Source | Windows Security |
| Primary System | Domain Controller |
| Logon Context | Account authentication |

## 4. Detection Query – Identify Account Lockouts

```spl
index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4740
| table _time host TargetUserName Caller_Computer_Name
| sort - _time
