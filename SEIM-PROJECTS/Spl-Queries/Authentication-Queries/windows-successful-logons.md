Detection 002: Windows Successful Logon Monitoring

1. Detection Overview

Detection Name: Windows Successful Logon Monitoring
SIEM: Splunk Enterprise
Query Language: SPL
Log Source: Windows Security Event Logs
Event ID: 4624
Severity: Informational – Context-dependent
MITRE ATT&CK: T1078 – Valid Accounts

2. Objective

Monitor successful Windows authentication events to identify unusual access patterns, unexpected account usage and potentially unauthorized access.

A successful login is not automatically malicious. The objective is to establish visibility into who accessed a system, when access occurred and where the authentication originated.

3. Data Sources

- Windows Security Event Logs
- Event ID 4624
- Splunk Universal Forwarder
- Splunk Enterprise

Replace "YOUR_INDEX" and "YOUR_WINDOWS_SECURITY_SOURCETYPE" with your actual Splunk values.

4. SPL Query A: Identify Successful Logons

index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4624
| table _time host Account_Name Source_Network_Address Logon_Type
| sort - _time

Purpose: Display successful Windows authentication events.

5. SPL Query B: Monitor Successful Logons by Account

index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4624
| stats count AS successful_logons values(host) AS systems values(Source_Network_Address) AS source_ips by Account_Name
| sort - successful_logons

Purpose: Identify accounts with successful authentication activity across monitored systems.

6. SPL Query C: Monitor Successful Logons by Source IP

index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4624
| stats count AS login_count values(Account_Name) AS accounts values(host) AS destination_hosts by Source_Network_Address
| sort - login_count

Purpose: Identify source addresses associated with successful logons.

7. SPL Query D: Investigate Remote Interactive Logons

index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" EventCode=4624 Logon_Type=10
| table _time host Account_Name Source_Network_Address Logon_Type
| sort - _time

Purpose: Investigate Remote Desktop interactive logons.

Logon Type 10 represents RemoteInteractive authentication.

8. Important Windows Logon Types

Logon Type| Description
2| Interactive logon
3| Network logon
4| Batch logon
5| Service logon
7| Unlock workstation
8| NetworkCleartext
9| NewCredentials
10| RemoteInteractive
11| CachedInteractive

9. Suspicious Indicators

- Successful access from an unfamiliar source IP.
- Unexpected Remote Desktop authentication.
- Privileged accounts logging in at unusual times.
- Accounts accessing systems outside their normal responsibilities.
- Successful authentication following repeated failures.

10. False Positive Considerations

- Legitimate administrator activity.
- Scheduled maintenance.
- Remote employees accessing corporate systems.
- Service accounts.
- Authorized Remote Desktop sessions.

11. Investigation Procedure

1. Identify the authenticated username.
2. Identify the destination hostname.
3. Examine the source IP address.
4. Determine the logon type.
5. Compare the activity with the user's normal behaviour.
6. Search for preceding failed authentication events.
7. Investigate related privilege and process activity.

12. MITRE ATT&CK Mapping

- Tactic: Initial Access / Persistence / Privilege Escalation
- Technique: Valid Accounts
- Technique ID: T1078

13. Validation Plan

1. Log in to your Windows 10 lab endpoint.
2. Confirm Event ID 4624 in Windows Event Viewer.
3. Verify that Splunk receives the event.
4. Run the SPL searches.
5. Confirm the account, hostname and logon type.
6. Capture the results as evidence.

14. Detection Limitations

- Successful authentication does not prove malicious activity.
- Source IP fields may be empty for some logon types.
- Field extraction depends on the Splunk input configuration.
- Unusual activity requires contextual investigation.

15. Evidence Requirements

- Windows Event Viewer Event ID 4624.
- Splunk query execution screenshot.
- Successful authentication records.
- Account and source IP investigation.

Author

Hope - HopeLabs Detection Engineering
