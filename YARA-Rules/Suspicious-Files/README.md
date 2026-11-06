
Suspicious File Detection

1. Overview

This directory contains YARA rules designed to identify unusual file characteristics and potentially malicious content that may require further security investigation.

A suspicious file is not automatically malware. It may be legitimate software that requires additional examination before a security decision is made.

2. Detection Objectives

- Identify unusual file characteristics.
- Detect suspicious embedded strings.
- Examine potentially malicious file content.
- Support malware triage.
- Understand false positives and detection limitations.

3. What We Will Examine

- Suspicious executable files.
- Unusual embedded strings.
- Unexpected file characteristics.
- Potentially malicious scripts.
- Files containing suspicious indicators.
- Unusual file extensions and content combinations.

4. Tools Required

- YARA
- Ubuntu Linux
- Windows
- SHA256 utilities
- VirusTotal
- Visual Studio Code

5. SOC Analyst Investigation

When a suspicious file is identified:

1. Record the file name and location.
2. Identify its file type and size.
3. Calculate its SHA256 hash.
4. Scan it using available YARA rules.
5. Investigate any matching strings or patterns.
6. Check the hash using approved threat intelligence sources.
7. Determine whether the finding requires escalation.
8. Document the investigation and recommended actions.

6. Expected Learning Outcomes

Develop practical skills in file triage, static analysis, YARA rule testing and identifying files that require deeper malware investigation.

7. Important Note

A YARA match is an indicator for investigation, not automatic proof that a file is malicious.

Always consider the detection logic, file context and possibility of false positives.

8. Safety

All testing must take place in an isolated, authorised laboratory environment. Never execute unknown suspicious files on a production computer.
