
Trojan Detection

1. Overview

This directory contains YARA rules designed to identify suspicious file characteristics and indicators associated with Trojan malware.

A Trojan is malicious software disguised as a legitimate application or file to trick users into installing or executing it.

Unlike viruses, Trojans do not necessarily replicate themselves. They often rely on social engineering to gain access to systems.

2. Detection Objectives

- Identify suspicious Trojan-related strings.
- Recognise potentially malicious executable files.
- Understand Trojan delivery techniques.
- Identify suspicious embedded commands.
- Support malware analysis and threat hunting.

3. What We Will Detect

- Suspicious executable characteristics.
- Known Trojan-related strings.
- Embedded malicious-looking commands.
- Suspicious file metadata.
- Recognisable malware patterns.

4. Tools Required

- YARA
- Ubuntu Linux
- Windows
- SHA256 utilities
- VirusTotal

5. SOC Analyst Investigation

When a suspicious file is identified:

1. Record the file name and location.
2. Calculate its SHA256 hash.
3. Scan the file using YARA.
4. Investigate any matching strings.
5. Check the hash using approved threat intelligence sources.
6. Document the findings.
7. Recommend appropriate containment actions.

6. Expected Learning Outcomes

By completing the projects in this directory, I aim to develop practical skills in identifying suspicious files, analysing malware indicators and supporting SOC investigations.

7. Safety

All activities are for defensive cybersecurity education and authorised security research.

Never execute unknown Trojan samples on a normal computer. Use an isolated malware analysis environment.
