PowerShell Detection & Threat Hunting

1. Project Overview

PowerShell is a powerful Windows command-line shell and scripting language widely used by system administrators, IT professionals, and attackers.

Threat actors frequently abuse PowerShell to execute malicious commands, download payloads, perform reconnaissance, bypass security controls, and maintain persistence within compromised environments.

This project focuses on identifying, monitoring, and investigating suspicious PowerShell activities using Windows Event Logging and Security Information and Event Management (SIEM) technologies.

The objective is to develop practical detection capabilities that help SOC analysts identify potentially malicious PowerShell execution, investigate suspicious commands, and understand attacker techniques.

---

2. Project Objectives

The primary objectives of this project are to:

- Monitor PowerShell execution activities on Windows endpoints.
- Enable and analyze PowerShell logging.
- Identify suspicious PowerShell command execution.
- Detect encoded PowerShell commands.
- Investigate potentially malicious scripting activities.
- Develop custom detection rules.
- Correlate Windows events with SIEM alerts.
- Map detected activities to the MITRE ATT&CK framework.
- Document investigation findings and recommended responses.

---

3. Lab Architecture

The detection environment consists of Windows-based log generation and SIEM monitoring components.

Component| Purpose
Windows 10| Endpoint and PowerShell event generation
Windows PowerShell| Command execution and scripting
Sysmon| Endpoint activity monitoring
Splunk| Log collection, analysis, and detection
Wazuh| Security monitoring and alert generation
Ubuntu Server| SIEM infrastructure
Kali Linux| Controlled security testing

Log Flow

1. PowerShell commands are executed on the Windows endpoint.
2. Windows Event Logging records PowerShell activity.
3. Sysmon provides additional endpoint telemetry where applicable.
4. Logs are forwarded to Splunk and/or Wazuh.
5. Detection rules identify suspicious execution patterns.
6. The SOC analyst investigates the events and documents findings.

---

4. Windows PowerShell Logging Configuration

PowerShell logging provides visibility into commands and scripts executed on Windows endpoints.

The following logging capabilities are relevant to this investigation.

A. Script Block Logging

Script Block Logging records the contents of PowerShell script blocks.

Group Policy Configuration:

"Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell"

Enable:

"Turn on PowerShell Script Block Logging"

This generates PowerShell Operational events, particularly:

- Event ID 4104 – Script Block Logging.

B. Module Logging

Module Logging records pipeline execution events from selected PowerShell modules.

Enable:

"Turn on Module Logging"

Configure the modules you want to monitor.

Relevant event:

- Event ID 4103 – Module Logging.

C. PowerShell Process Creation Monitoring

Windows Security auditing can record process creation activities.

Enable:

"Audit Process Creation"

Relevant event:

- Event ID 4688 – A new process has been created.

Command-line auditing can provide additional visibility into the arguments used to launch PowerShell.

---

5. Important Windows Event IDs

Event ID| Description| Security Relevance
4103| PowerShell Module Logging| Tracks module execution
4104| PowerShell Script Block Logging| Records executed script blocks
4688| Process Creation| Identifies PowerShell process execution
1| Sysmon Process Creation| Provides detailed process telemetry
3| Sysmon Network Connection| Identifies process-associated network activity

These events provide valuable information for detecting suspicious scripting activities.

---

6. PowerShell Detection Scenarios

The following scenarios demonstrate suspicious PowerShell behaviors that a SOC analyst should investigate.

Detection 1: Encoded PowerShell Commands

Attackers may use Base64-encoded commands to conceal command-line instructions.

Common indicators include:

- "-EncodedCommand"
- "-enc"
- "-e"

Detection Objective:

Identify PowerShell processes executing encoded commands.

Splunk SPL Query:

index=main EventCode=4688
| search New_Process_Name="*powershell.exe*"
| search Process_Command_Line="*-enc*" OR Process_Command_Line="*-EncodedCommand*"
| table _time Computer New_Process_Name Process_Command_Line

Investigation:

- Identify the user executing the command.
- Examine the parent process.
- Review the command-line arguments.
- Determine whether the encoded content is suspicious.
- Correlate the event with other endpoint activities.

Detection 2: PowerShell Download Activity

PowerShell can be abused to download files from remote infrastructure.

Common indicators include:

- "DownloadString"
- "DownloadFile"
- "Invoke-WebRequest"
- "iwr"
- "Net.WebClient"

Splunk SPL Query:

index=main EventCode=4104
| search ScriptBlockText="*DownloadString*"
    OR ScriptBlockText="*DownloadFile*"
    OR ScriptBlockText="*Invoke-WebRequest*"
    OR ScriptBlockText="*Net.WebClient*"
| table _time Computer ScriptBlockText

Investigation:

- Identify the destination URL or domain.
- Examine the script content.
- Determine whether a file was downloaded.
- Correlate with Sysmon network connection events.
- Check the downloaded file against available threat intelligence.

Detection 3: PowerShell Execution with Hidden Windows

Attackers may attempt to conceal PowerShell execution by launching it with hidden window parameters.

Common indicators:

- "-WindowStyle Hidden"
- "-w hidden"
- "-NoProfile"

Splunk SPL Query:

index=main EventCode=4688
| search New_Process_Name="*powershell.exe"
| search Process_Command_Line="*-WindowStyle Hidden*"
    OR Process_Command_Line="*-w hidden*"
| table _time Computer SubjectUserName Process_Command_Line

Investigation:

Determine whether the hidden execution was initiated by an authorized administrative script or an unknown process.

Detection 4: PowerShell Execution Policy Bypass

PowerShell execution policies can be overridden through command-line parameters.

Common indicator:

"-ExecutionPolicy Bypass"

Splunk SPL Query:

index=main EventCode=4688
| search New_Process_Name="*powershell.exe"
| search Process_Command_Line="*-ExecutionPolicy Bypass*"
    OR Process_Command_Line="*-ep bypass*"
| table _time Computer SubjectUserName Process_Command_Line

Investigation:

- Identify the initiating account.
- Examine the complete command line.
- Review the parent process.
- Determine whether the execution was authorized.

Important: Execution policy bypass is not automatically malicious. Legitimate administrative activities can also use this parameter.

---

7. MITRE ATT&CK Mapping

Technique ID| Technique| Description
T1059.001| PowerShell| Command and scripting interpreter abuse
T1027| Obfuscated Files or Information| Concealing malicious commands
T1140| Deobfuscate/Decode Files or Information| Decoding concealed content
T1105| Ingress Tool Transfer| Downloading additional tools or payloads
T1059| Command and Scripting Interpreter| Execution through command interpreters

MITRE ATT&CK provides a framework for understanding attacker behavior and mapping detection coverage.

Reference: https://attack.mitre.org/

---

8. SOC Investigation Workflow

When a suspicious PowerShell event is detected, the analyst should follow a structured investigation process.

Step 1: Alert Identification

Identify the event that triggered the detection rule.

Record:

- Event timestamp.
- Hostname.
- Username.
- Process name.
- Command-line arguments.

Step 2: Process Investigation

Investigate the PowerShell process.

Determine:

- Which process launched PowerShell?
- Was the process initiated by an interactive user?
- Was the parent process suspicious?
- Were unusual command-line arguments used?

Step 3: User Investigation

Establish whether the account has legitimate administrative privileges.

Check:

- User account.
- Logon activity.
- Account privileges.
- Unusual login times.

Step 4: Network Investigation

Correlate suspicious PowerShell activity with network events.

Look for:

- Unknown external IP addresses.
- Suspicious domains.
- Unexpected outbound connections.
- Unusual download activity.

Step 5: Determine the Severity

Classify the activity based on available evidence.

Severity| Description
Critical| Confirmed malicious PowerShell activity associated with compromise
High| Strong indicators of malicious scripting
Medium| Suspicious execution requiring further investigation
Low| Unusual but potentially legitimate administrative activity

Step 6: Response and Documentation

Depending on the findings:

- Escalate confirmed malicious activity.
- Isolate compromised endpoints when necessary.
- Disable compromised accounts where appropriate.
- Preserve relevant logs.
- Document the investigation.
- Recommend additional detection improvements.

---

9. Detection Engineering Considerations

Effective PowerShell detection requires more than searching for suspicious keywords.

Detection rules should consider:

- Parent-child process relationships.
- User context.
- Command-line arguments.
- Script block contents.
- Network connections.
- Execution frequency.
- Known administrative tools and scripts.

False Positive Management

Legitimate system administrators may use PowerShell for automation, software installation, system administration, and troubleshooting.

To reduce false positives:

1. Establish normal PowerShell activity.
2. Identify approved administrative scripts.
3. Correlate multiple indicators.
4. Avoid relying on a single suspicious keyword.
5. Continuously review detection performance.

---

10. Expected Learning Outcomes

Upon completing this project, the following practical skills should be demonstrated:

- Windows endpoint monitoring.
- PowerShell security auditing.
- Windows Event Log analysis.
- Sysmon event investigation.
- Splunk SPL query development.
- Wazuh security monitoring.
- Threat hunting.
- Detection engineering.
- MITRE ATT&CK mapping.
- SOC incident investigation.
- Security documentation and reporting.

---

11. Project Status

Project Category: Detection Engineering / Threat Hunting

Difficulty: Intermediate

Environment: Windows 10, Ubuntu Server, Kali Linux

Monitoring Tools: Splunk, Wazuh, Sysmon

Detection Focus: Suspicious PowerShell Execution

Status: Practical Lab / Detection Development

---

12. Conclusion

PowerShell remains an important component of Windows administration, but its extensive capabilities also make it attractive to threat actors.

Developing effective PowerShell detection mechanisms gives SOC analysts greater visibility into endpoint activities and helps identify suspicious execution patterns before they escalate into more serious security incidents.

This project demonstrates the practical application of Windows logging, SIEM queries, endpoint telemetry, threat hunting, and MITRE ATT&CK techniques in a controlled cybersecurity home lab.

The ultimate goal is to develop detection capabilities that improve endpoint visibility, strengthen incident investigation, and support proactive threat detection.

---

Author: Aigbokhaode Hope
Focus: SOC Operations | Detection Engineering | Threat Hunting
Repository: Enterprise Detection Engineering & SOC Operations Lab
