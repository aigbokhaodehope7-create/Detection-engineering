# Wazuh Authentication Queries

## Overview

This folder contains DQL searches for investigating authentication-related security events in Wazuh.

These queries help SOC analysts identify failed login attempts, suspicious login activity and possible brute-force attacks.

## Detection Categories

- Failed login attempts
- Repeated authentication failures
- Successful authentication
- Brute-force investigation
- Password spraying investigation
- Suspicious login sources
- Authentication activity by user

## Investigation Objectives

- Identify accounts experiencing repeated login failures.
- Identify suspicious source IP addresses.
- Investigate unusual authentication patterns.
- Correlate failed and successful login activity.
- Identify possible compromised accounts.

## Important

These searches retrieve existing Wazuh alerts. Detection and alert generation depend on the configured Wazuh rules and collected event data.

## Author

Hope - HopeLabs Detection Engineering
