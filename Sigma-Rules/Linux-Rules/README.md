# Linux Sigma Rules

This directory contains Sigma detection rules for identifying suspicious activities on Linux systems.

## Detection Categories

- Suspicious command execution
- SSH brute-force attempts
- Privilege escalation
- Suspicious user account creation
- Cron job persistence
- Linux service manipulation
- Suspicious network connections
- Log deletion and tampering
- Web shell activity
- Linux malware execution

## Log Sources

- Linux Syslog
- SSH authentication logs
- Auditd
- Linux process creation logs
- Systemd journal

## Purpose

These rules help SOC Analysts detect suspicious Linux activities, investigate security incidents, and identify potential attack techniques.

## Rule Format

All detection rules are written in YAML using the Sigma specification.

## Author

Hope - HopeLabs Detection Engineering
