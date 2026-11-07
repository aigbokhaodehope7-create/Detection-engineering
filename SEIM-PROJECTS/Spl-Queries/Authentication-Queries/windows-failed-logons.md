Detection 001: Windows Failed Logon Monitoring

1. Detection Overview

Detection Name: Windows Failed Logon Monitoring
SIEM: Splunk Enterprise
Query Language: SPL
Log Source: Windows Security Event Logs
Event ID: 4625
Severity: Medium – Context-dependent
MITRE ATT&CK: T1110 – Brute Force

2. Objective

Detect and investigate failed Windows authentication attempts to identify suspicious login behaviour, possible password guessing and unauthorized access attempts.

3. Required Telemetry

- Windows Security Event Logs
- Event ID 4625
- Splunk Universal Forwarder or another supported log collection method

The following query uses placeholder index and sourcetype values. Replace them with the actual values in your Splunk environment.

4. SPL Query A: Identify Failed Logons

index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4625
| table _time host Account_Name Source_Network_Address Logon_Type
| sort - _time

Purpose: Display individual failed authentication events.

5. SPL Query B: Group Failed Logons by Source IP

index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4625
| stats count AS failed_attempts values(Account_Name) AS targeted_accounts by Source_Network_Address
| sort - failed_attempts

Purpose: Identify source addresses generating repeated failed authentication attempts.

6. SPL Query C: Investigate Failed Logons by Account

index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4625
| stats count AS failed_attempts values(Source_Network_Address) AS source_ips by Account_Name
| sort - failed_attempts

Purpose: Identify accounts receiving repeated failed authentication attempts.

7. SPL Query D: Identify Potential Brute-Force Activity

index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4625
| bin _time span=5m
| stats count AS failed_attempts dc(Account_Name) AS unique_accounts by _time Source_Network_Address
| where failed_attempts >= 10
| sort - failed_attempts

Purpose: Identify sources generating at least ten failed logons within a five-minute bucket.

This is a hunting threshold, not proof of malicious activity.

8. Important Fields

Field| Description
_time| Event timestamp
host| Reporting endpoint
EventCode| Windows event identifier
Account_Name| Account associated with the event
Source_Network_Address| Originating network address
Logon_Type| Authentication type

Field extraction depends on the Splunk input configuration and Windows add-on.

9. False Positive Considerations

- Incorrect passwords.
- Expired credentials.
- Misconfigured applications.
- Service accounts using outdated passwords.
- Authorized penetration testing.

10. Investigation Procedure

1. Identify the source IP.
2. Identify the affected accounts.
3. Examine the number and frequency of failed attempts.
4. Review the destination hostname.
5. Check for successful logons following the failures.
6. Investigate other suspicious activity from the source.
7. Document the findings.

11. MITRE ATT&CK Mapping

- Tactic: Credential Access
- Technique: Brute Force
- Technique ID: T1110

12. Validation Plan

1. Generate a controlled failed login in the Windows lab.
2. Confirm Event ID 4625 in Windows Event Viewer.
3. Verify the event reaches Splunk.
4. Confirm the index, sourcetype and extracted fields.
5. Run the SPL queries.
6. Compare results with the original Windows event.

13. Evidence Requirements

- Windows Event Viewer screenshot.
- Splunk search results.
- Source IP and account information.
- Query execution screenshot.
- Investigation findings.

14. Detection Limitations

- Missing source IP values can affect grouping.
- Field names vary with input configurations.
- A single failed login does not establish an attack.
- The five-minute threshold requires tuning to the environment.

Author

Hope - HopeLabs Detection Engineering
