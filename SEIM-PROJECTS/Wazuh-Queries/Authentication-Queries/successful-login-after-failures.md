# Detection 002: Successful Login After Failed Attempts

## 1. Objective

Identify accounts that experience repeated failed authentication attempts followed by a successful login.

This pattern may indicate a successful password-guessing attack or unauthorized account access.

## 2. Data Sources

- Windows Security Event ID 4625: Failed logon
- Windows Security Event ID 4624: Successful logon
- SIEM: Wazuh
- Query Language: DQL

## 3. Query A: Search Failed Logons

data.win.system.eventID: "4625"

## 4. Query B: Search Successful Logons

data.win.system.eventID: "4624"

## 5. Investigation Logic

Search for:

1. Multiple failed logons involving the same account.
2. A subsequent successful logon involving that account.
3. Matching source IP addresses, where available.
4. A short time interval between the failures and success.
5. Unexpected login times or unusual logon types.

## 6. Correlation Requirements

Compare these fields across the events:

| Field | Purpose |
|---|---|
| targetUserName | Identify the account |
| ipAddress | Compare source addresses |
| systemTime | Establish event sequence |
| computer | Identify the affected endpoint |
| logonType | Understand the authentication method |

Field paths may differ between event types and Wazuh decoders.

## 7. Suspicious Indicators

- Several failed attempts followed by a successful login.
- A successful login from an unusual source IP.
- Authentication involving a privileged account.
- Successful access outside normal working hours.

## 8. False Positives

- Users eventually entering the correct password.
- Password managers submitting incorrect credentials.
- Applications retrying authentication.
- Authorized administrators testing access.

## 9. MITRE ATT&CK

- T1110: Brute Force
- T1078: Valid Accounts

## 10. Important Detection Limitation

The two DQL queries above retrieve separate event sets. They do not automatically correlate the events or prove that a successful login followed the failures.

The analyst must compare timestamps, account names, source addresses and endpoint information, or use a dedicated correlation mechanism.

## 11. Validation

1. Generate several controlled failed logons.
2. Successfully authenticate to the test Windows account.
3. Confirm Event IDs 4625 and 4624.
4. Verify that Wazuh receives both events.
5. Compare the timestamps and account information.
6. Document whether the pattern is suspicious or legitimate.

## 12. Evidence

- Failed-login alert.
- Successful-login alert.
- Timestamp comparison.
- Investigation notes.

## Author

Hope - HopeLabs Detection Engineering
