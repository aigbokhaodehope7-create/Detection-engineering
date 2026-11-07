Detection 003: Successful Login After Multiple Failed Attempts

1. Detection Overview

SIEM: Splunk Enterprise
Query Language: SPL
Log Source: Windows Security Logs
Event IDs: 4625 and 4624
Severity: High – Context-dependent
MITRE ATT&CK: T1110, T1078

2. Objective

Identify authentication patterns where multiple failed login attempts are followed by a successful login.

This behaviour may indicate password guessing, brute-force activity or unauthorized access.

3. Detection Logic

The investigation correlates:

- Event ID 4625 – Failed logon.
- Event ID 4624 – Successful logon.

The analyst looks for repeated failures followed by successful authentication involving the same account and, where available, the same source IP.

4. SPL Query: Correlate Failed and Successful Logons

index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" (EventCode=4624 OR EventCode=4625)
| eval event_type=case(EventCode=4625,"Failed Logon",EventCode=4624,"Successful Logon")
| eval user=coalesce(Account_Name, TargetUserName, user)
| eval src_ip=coalesce(Source_Network_Address, IpAddress, src_ip)
| where isnotnull(user) AND user!="-"
| sort 0 user src_ip _time
| streamstats time_window=10m count(eval(EventCode=4625)) AS failed_attempts window=0 by user src_ip
| where EventCode=4624 AND failed_attempts>=5
| table _time host user src_ip failed_attempts event_type
| sort - _time

Purpose: Identify successful logons preceded by at least five failed attempts within the preceding ten minutes for the same account and source IP.

Note: This query is a starting correlation example. Validate field extraction and "streamstats" behaviour against your Splunk version and event data before deploying it.

5. SPL Query: Review Authentication Timeline

index=YOUR_INDEX sourcetype="YOUR_WINDOWS_SECURITY_SOURCETYPE" (EventCode=4624 OR EventCode=4625)
| eval event_type=if(EventCode=4625,"Failed","Successful")
| eval user=coalesce(Account_Name, TargetUserName, user)
| eval src_ip=coalesce(Source_Network_Address, IpAddress, src_ip)
| where isnotnull(user)
| sort 0 _time
| table _time host user src_ip event_type Logon_Type

Purpose: Review the sequence of authentication events during an investigation.

6. Investigation Fields

Field| Purpose
_time| Authentication timestamp
host| Destination endpoint
user| Account involved
src_ip| Source address
EventCode| Windows event identifier
Logon_Type| Authentication method

7. Suspicious Indicators

- Multiple failed attempts followed by a successful login.
- Authentication from an unfamiliar source.
- Successful access to a privileged account.
- Login activity outside normal working hours.
- Additional suspicious activity after authentication.

8. False Positive Considerations

- Users repeatedly entering incorrect passwords.
- Password managers submitting outdated credentials.
- Legitimate account recovery.
- Authorized security testing.
- Applications retrying authentication.

9. MITRE ATT&CK Mapping

- T1110 – Brute Force
- T1110.001 – Password Guessing
- T1078 – Valid Accounts

10. Investigation Procedure

1. Identify the affected account.
2. Review the failed authentication count.
3. Compare the source IP addresses.
4. Establish the timeline.
5. Confirm whether the successful login occurred after the failures.
6. Review the logon type and destination host.
7. Investigate subsequent account and process activity.
8. Document the findings and escalate where necessary.

11. Validation Plan

1. Generate controlled failed logons in the Windows lab.
2. Successfully log in using the test account.
3. Confirm Event IDs 4625 and 4624.
4. Confirm both event types reach Splunk.
5. Verify field extraction.
6. Run the correlation query.
7. Compare the result with the original Windows event timeline.

12. Detection Limitations

- Missing source IP values can prevent correlation.
- Account field names may differ between event formats.
- Events from different endpoints may require additional correlation logic.
- The threshold of five failures is configurable.
- A matching pattern is suspicious, not conclusive proof of compromise.

13. Evidence Requirements

- Failed authentication events.
- Successful authentication event.
- SPL correlation results.
- Authentication timeline.
- Investigation conclusion.

Author

Hope - HopeLabs Detection Engineering
