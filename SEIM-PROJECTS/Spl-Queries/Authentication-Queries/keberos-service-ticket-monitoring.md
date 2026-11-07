# Detection 009 – Kerberos Service Ticket Monitoring

## 1. Overview

Windows Security Event ID 4769 records Kerberos service ticket requests.

Kerberos is an authentication protocol used in Active Directory environments.

Attackers may abuse service ticket requests to perform Kerberoasting, where they request service tickets for accounts with Service Principal Names (SPNs) and attempt to crack the encrypted ticket material offline.

## 2. Objective

Monitor Kerberos service ticket activity and identify unusual request patterns that may indicate credential attacks or abuse.

## 3. Event Information

| Field | Description |
|---|---|
| Event ID | 4769 |
| Event Name | A Kerberos service ticket was requested |
| Log Source | Windows Security |
| Primary System | Domain Controller |
| Protocol | Kerberos |

## 4. Detection Query – Identify Kerberos Ticket Requests

```spl
index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4769
| table _time host Account_Name Service_Name Client_Address Ticket_Encryption_Type Status
| sort - _time
