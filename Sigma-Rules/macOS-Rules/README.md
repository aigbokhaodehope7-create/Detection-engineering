# macOS Sigma Rules

This directory contains Sigma detection rules designed to identify suspicious activities on macOS endpoints.

## Detection Categories

- Suspicious Terminal commands
- SSH authentication attacks
- Unauthorized user creation
- Privilege escalation
- LaunchAgent and LaunchDaemon persistence
- Suspicious AppleScript execution
- Gatekeeper security bypass
- Suspicious application execution
- File and directory modifications
- Suspicious network connections
- macOS malware execution
- Log tampering

## Log Sources

- macOS Unified Logs
- Endpoint Security Framework
- OpenBSM Audit Logs
- Process execution telemetry
- File system monitoring
- SSH authentication logs

## Purpose

These rules help SOC Analysts identify suspicious macOS activities, investigate security incidents, and detect potential attacker techniques.

## Rule Format

All detection rules are written in YAML using the Sigma specification.

## Author

Hope - HopeLabs Detection Engineering
