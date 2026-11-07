# Detection 008 – Privileged Logon Monitoring

## 1. Overview

Windows Security Event ID 4672 is generated when special privileges are assigned to a new logon session.

These privileges may allow a user or process to perform sensitive administrative operations.

Examples include:
- SeDebugPrivilege
- SeBackupPrivilege
- SeRestorePrivilege
- SeTakeOwnershipPrivilege
- SeLoadDriverPrivilege

Event ID 4672 does not automatically indicate malicious activity. It must be investigated alongside the account, logon session, and surrounding events.

## 2. Objective

Identify logon sessions receiving sensitive privileges and investigate unexpected privileged activity.

## 3. Event Information

| Field | Description |
|---|---|
| Event ID | 4672 |
| Event Name | Special privileges assigned to new logon |
| Log Source | Windows Security |
| Data Source | Windows endpoints and servers |
| Severity | Context-dependent |

## 4. Detection Query – Identify Privileged Logons

```spl
index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4672
| table _time host SubjectUserName SubjectDomainName SubjectLogonId PrivilegeList
| sort - _time
