# Detection 013 – User Account Modification Monitoring

## 1. Overview

Windows Security Event ID 4738 is generated when a user account is changed.

Account modifications may involve changes to account attributes, settings, or other properties.

Attackers with sufficient permissions may modify accounts to maintain access or weaken security controls.

## 2. Objective

Identify account modifications, determine who performed them, and investigate whether the changes were authorized.

## 3. Windows Event Information

| Field | Description |
|---|---|
| Event ID | 4738 |
| Event Name | A user account was changed |
| Log Source | Windows Security |
| Systems | Windows endpoints and Domain Controllers |
| Severity | Context-dependent |

## 4. Detection Query – Identify Account Modifications

```spl
index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4738
| table _time host SubjectUserName TargetUserName
        TargetDomainName
| sort - _time
