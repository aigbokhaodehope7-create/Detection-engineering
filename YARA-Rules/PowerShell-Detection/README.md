PowerShell Detection

1. Overview

This directory contains YARA rules designed to identify suspicious PowerShell-related content and potentially malicious scripts.

PowerShell is a legitimate Windows command-line shell and scripting environment used by administrators and security professionals.

However, attackers sometimes abuse PowerShell to execute malicious commands, download files, evade detection and perform unauthorised activities.

2. Detection Objectives

- Identify suspicious PowerShell strings.
- Recognise encoded commands.
- Understand PowerShell abuse techniques.
- Identify suspicious download instructions.
- Support endpoint security investigations.

3. What We Will Detect

- Encoded PowerShell command patterns.
- Suspicious download commands.
- Hidden execution parameters.
- Potentially malicious script content.
- Suspicious command combinations.

4. Tools Required

- YARA
- PowerShell
- Windows
- Sysmon
- Wazuh
- Splunk
- Visual Studio Code

5. SOC Analyst Investigation

When suspicious PowerShell activity is identified:

1. Examine the PowerShell command or script.
2. Identify the user and affected endpoint.
3. Review the process and parent process.
4. Check Sysmon and Windows Event Logs.
5. Calculate the SHA256 hash of any suspicious script file.
6. Investigate relevant indicators.
7. Document findings and recommend containment.

6. Important Detection Note

YARA primarily identifies patterns in files and memory. It does not independently monitor live PowerShell execution.

For live activity monitoring, correlate YARA findings with Sysmon, Windows Event Logs and SIEM platforms such as Wazuh or Splunk.

7. Expected Learning Outcomes

Develop practical skills in recognising suspicious PowerShell content, understanding attacker techniques and supporting endpoint investigations.

8. Safety

All testing must be conducted in an authorised laboratory environment. Use harmless test scripts and never execute unknown malicious scripts on a production computer.
