
# Ransomware Detection

## Overview

This directory contains YARA rules designed to identify
file characteristics and indicators associated with ransomware.

Ransomware is malware that encrypts or otherwise prevents
access to files and demands payment from victims.

## Detection Objectives

- Identify ransomware-related strings.
- Recognise suspicious file characteristics.
- Understand common ransomware indicators.
- Support malware triage and investigation.

## What We Will Detect

- Ransom-note text patterns.
- Known ransomware-related strings.
- Suspicious encryption-related indicators.
- Recognisable malware file patterns.

## Tools

- YARA
- Linux
- Windows
- Malware analysis tools

## SOC Analyst Investigation

When a suspicious file is identified:

1. Record its file name and location.
2. Calculate its SHA256 hash.
3. Check the hash using approved threat intelligence sources.
4. Examine the YARA detection result.
5. Document findings and recommend containment.

## Safety

Never execute ransomware samples on your normal computer.
Use isolated, authorised malware analysis environments.
