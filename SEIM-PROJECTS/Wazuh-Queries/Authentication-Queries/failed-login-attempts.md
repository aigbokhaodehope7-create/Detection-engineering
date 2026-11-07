# Detection 001: Windows Failed Login Attempts

## 1. Objective

Detect failed Windows authentication attempts using Wazuh alerts.

This detection helps SOC analysts investigate unauthorized access attempts, password guessing and possible brute-force activity.

## 2. Data Source

- Platform: Windows
- Log Source: Windows Security Event Logs
- Event ID: 4625
- SIEM: Wazuh
- Query Language: DQL

## 3. DQL Query

Search for Windows failed logon events:

data.win.system.eventID: "4625"

## 4. Detection Explanation

Windows Event ID 4625 is generated when a logon attempt fails.

The query searches Wazuh alerts for events containing this Windows Event ID.

## 5. Important Fields

| Field | Purpose |
|---|---|
| eventID | Identifies the Windows event |
| targetUserName | Account targeted |
| ipAddress | Source IP address, if available |
| logonType | Type of attempted logon |
| status | Failure status |
| subStatus | Detailed failure reason |

## 6. Investigation Procedure

1. Identify the affected username.
2. Examine the source IP address.
3. Check the number of failed attempts.
4. Review the timestamps.
5. Search for successful logons involving the same account.
6. Investigate other suspicious activity from the source.

## 7. False Positives

- Incorrect passwords.
- Expired passwords.
- Applications using outdated credentials.
- Misconfigured scheduled tasks.
- Authorized security testing.

## 8. MITRE ATT&CK

- Tactic: Credential Access
- Technique: Brute Force
- Technique ID: T1110

## 9. Validation

1. Generate a controlled failed login in the Windows lab.
2. Confirm Event ID 4625 in Windows Event Viewer.
3. Confirm that Wazuh receives the event and generates an alert.
4. Run the DQL query in Wazuh Dashboard.
5. Compare the alert fields with the original Windows event.

## 10. Evidence

Capture:

- Windows Event Viewer showing Event ID 4625.
- Wazuh alert details.
- DQL query and matching results.

## Author

Hope - HopeLabs Detection Engineering
