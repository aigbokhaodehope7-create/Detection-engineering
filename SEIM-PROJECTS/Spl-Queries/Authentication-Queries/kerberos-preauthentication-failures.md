# Detection 010 – Kerberos Pre-Authentication Failure Monitoring

## 1. Overview

Windows Security Event ID 4771 is generated when Kerberos pre-authentication fails.

Repeated failures may indicate:
- Password guessing.
- Brute-force attempts.
- Password spraying.
- Expired or incorrect credentials.
- Misconfigured applications or services.

A single failure does not establish malicious activity.

## 2. Objective

Monitor Kerberos pre-authentication failures and identify suspicious authentication patterns involving user accounts and client addresses.

## 3. Event Information

| Field | Description |
|---|---|
| Event ID | 4771 |
| Event Name | Kerberos pre-authentication failed |
| Log Source | Windows Security |
| Primary System | Domain Controller |
| Protocol | Kerberos |

## 4. Detection Query – Identify Kerberos Failures

```spl
index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4771
| table _time host TargetUserName IpAddress Failure_Code
| sort - _time
