Detection 005: Single-Account Brute-Force Detection

1. Detection Overview

SIEM: Splunk Enterprise
Query Language: SPL
Log Source: Windows Security Logs
Event ID: 4625
Severity: High – Context-dependent
MITRE ATT&CK: T1110.001 – Password Guessing

2. Objective

Identify repeated failed authentication attempts targeting a single Windows account within a defined period.

3. Attack Description

A brute-force attack attempts multiple password combinations against a target account until valid credentials are discovered.

An attacker may use automated tools to generate repeated authentication requests.

4. Required Telemetry

- Windows Security Event Logs
- Event ID 4625
- Splunk Universal Forwarder
- Extracted account and source IP fields

5. SPL Query A: Group Failed Attempts by Account and Source

index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4625
| bin _time span=5m
| stats count AS failed_attempts values(host) AS affected_hosts by _time Account_Name Source_Network_Address
| where failed_attempts >= 10
| sort - failed_attempts

Purpose: Identify at least ten failed authentication attempts against the same account from the same source IP within a five-minute bucket.

6. SPL Query B: Identify the Most Targeted Accounts

index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4625
| stats count AS total_failures dc(Source_Network_Address) AS unique_sources values(Source_Network_Address) AS source_ips by Account_Name
| sort - total_failures

Purpose: Identify accounts experiencing high numbers of authentication failures.

7. SPL Query C: Investigate a Specific Account

index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4625 Account_Name="Administrator"
| table _time host Account_Name Source_Network_Address Logon_Type
| sort - _time

Purpose: Review failed authentication events involving a particular account.

8. Detection Threshold

Initial hunting threshold:

- 10 or more failed attempts.
- Same username.
- Same source IP.
- Within five minutes.

Tune the threshold based on normal authentication activity.

9. Investigation Fields

Field| Purpose
_time| Event timestamp
Account_Name| Targeted username
Source_Network_Address| Originating IP
host| Destination endpoint
Logon_Type| Authentication method
EventCode| Windows event identifier

10. Suspicious Indicators

- Repeated failures against one account.
- Short intervals between attempts.
- Attempts targeting privileged accounts.
- Multiple source addresses targeting the same account.
- Successful login after repeated failures.

11. False Positive Considerations

- Users repeatedly entering incorrect passwords.
- Expired passwords.
- Applications using outdated credentials.
- Misconfigured services.
- Authorized penetration testing.

12. MITRE ATT&CK Mapping

- Tactic: Credential Access
- Technique: Brute Force
- Sub-technique: Password Guessing
- Technique ID: T1110.001

13. Investigation Procedure

1. Identify the affected account.
2. Identify the source IP.
3. Determine the number of failures.
4. Establish the time interval.
5. Examine the destination hostname.
6. Search for successful authentication.
7. Review related security events.
8. Document and escalate suspicious findings.

14. Validation Plan

1. Generate controlled failed logons in your Windows lab.
2. Confirm Event ID 4625.
3. Verify that Splunk receives the events.
4. Execute the SPL queries.
5. Confirm the username, source IP and event count.
6. Capture the results.

15. Detection Limitations

- Field extraction varies by Splunk input configuration.
- Fixed time buckets can miss events across bucket boundaries.
- A high failure count does not prove malicious activity.
- Distributed attacks may require additional correlation logic.

16. Evidence Requirements

- Windows Event ID 4625 records.
- Splunk search results.
- Source IP and account information.
- Authentication timeline.
- Investigation conclusion.

Author

Hope - HopeLabs Detection Engineering
