# PowerShell Detection Lab (Wazuh)

Detecting suspicious PowerShell activity on a Windows 10 endpoint using Wazuh, Sysmon, and custom detection rules mapped to MITRE ATT&CK.

![Platform](https://img.shields.io/badge/SIEM-Wazuh-blue)
![Endpoint](https://img.shields.io/badge/Endpoint-Windows%2010-0078D6)
![Telemetry](https://img.shields.io/badge/Telemetry-Sysmon%20%2B%20PowerShell-green)
![MITRE](https://img.shields.io/badge/MITRE-T1059.001-red)

---

## Overview

PowerShell is a legitimate admin tool that attackers abuse heavily (living-off-the-land). This lab builds an end-to-end detection pipeline:

1. Enable PowerShell and Sysmon logging on the endpoint
2. Forward the logs to Wazuh with the agent
3. Write custom rules to detect suspicious usage
4. Map detections to MITRE ATT&CK
5. Document false positives and tuning

## Lab Architecture

| Component | Role | Notes |
|---|---|---|
| Ubuntu VM | Wazuh manager + dashboard | `192.168.56.101` |
| Windows 10 VM | Monitored endpoint (Wazuh agent, Sysmon) | Test host |
| VirtualBox | Hypervisor | Host-only network |

```
 Windows 10 (agent)  ──── logs (1514/tcp) ────▶  Wazuh Manager (Ubuntu)
  ├─ PowerShell 4103/4104                            ├─ Decoders
  ├─ Sysmon (Event ID 1)                             ├─ Rules (local_rules.xml)
  └─ Security 4688                                   └─ Dashboard / alerts
```

## Prerequisites

- Wazuh manager installed and reachable from the endpoint
- Wazuh agent installed and **Active** on Windows 10
- Sysmon installed with a maintained config (e.g. SwiftOnSecurity)
- Administrator access on the Windows VM

---

## Step 1: Enable PowerShell Logging

Run in an elevated PowerShell session.

**Script Block Logging (Event ID 4104):**

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```

**Module Logging (Event ID 4103):**

```powershell
$base = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $base -Force | Out-Null
Set-ItemProperty -Path $base -Name "EnableModuleLogging" -Value 1
New-Item -Path "$base\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$base\ModuleNames" -Name "*" -Value "*"
```

**Process creation with command line (Event ID 4688):**

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
```

**Verify:**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5
```

## Step 2: Configure Wazuh Agent Collection

Edit `C:\Program Files (x86)\ossec-agent\ossec.conf` and add inside `<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the agent:

```powershell
Restart-Service -Name WazuhSvc
```

Confirm on the manager:

```bash
sudo /var/ossec/bin/agent_control -l
```

> **Tip:** If events don't appear, enable archive logging (`<logall_json>yes</logall_json>` in the manager's `ossec.conf`) and check `/var/ossec/logs/archives/archives.json` to confirm the raw events are arriving before debugging rules.

## Step 3: Custom Detection Rules

Add to `/var/ossec/etc/rules/local_rules.xml` on the manager. Use rule IDs in the custom range (100000+).

```xml
<group name="powershell,windows,">

  <!-- Hidden-window PowerShell -->
  <rule id="100600" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-w(indowstyle)?\s+hidden</field>
    <description>PowerShell launched with hidden window</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1564.003</id>
    </mitre>
  </rule>

  <!-- Encoded PowerShell spawning recon commands -->
  <rule id="100610" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.parentCommandLine" type="pcre2">(?i)-(enc|encodedcommand)\s</field>
    <field name="win.eventdata.image" type="pcre2">(?i)(whoami|hostname)\.exe$</field>
    <description>Encoded PowerShell spawned recon command (whoami/hostname)</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1033</id>
      <id>T1082</id>
    </mitre>
  </rule>

</group>
```

Validate and apply:

```bash
sudo /var/ossec/bin/wazuh-logtest      # paste a sample event to test
sudo systemctl restart wazuh-manager
```

## Step 4: Generate Test Activity

Run on the Windows 10 VM (lab use only):

```powershell
# Triggers 100600: hidden window
powershell.exe -WindowStyle Hidden -Command "Get-Process"

# Triggers 100610: encoded command spawning whoami/hostname
$cmd = 'whoami; hostname'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $enc
```

## Step 5: Verify Detection

In the Wazuh dashboard, go to **Threat Hunting → Events** and filter:

```
rule.id: (100600 OR 100610)
```

Or on the manager:

```bash
sudo grep -E '"id":"(100600|100610)"' /var/ossec/logs/alerts/alerts.json | tail -n 5
```

## Detection Summary

| Rule ID | Level | Behavior | MITRE ATT&CK |
|---|---|---|---|
| 100600 | 10 | PowerShell launched with hidden window | T1059.001, T1564.003 |
| 100610 | 12 | Encoded PowerShell spawning `whoami`/`hostname` | T1059.001, T1033, T1082 |

## False Positives & Tuning

| Rule | Possible benign cause | Tuning |
|---|---|---|
| 100600 | Admin or deployment scripts using `-WindowStyle Hidden`; software installers | Allowlist known parent processes or script paths |
| 100610 | Management tools running encoded commands for inventory | Exclude known service accounts or parent images |

General guidance:
- Baseline normal PowerShell usage before raising rule levels
- Correlate with parent process, user, and host, not just the command line
- Prefer narrow allowlists (parent + path + user) over broad exclusions

## Evidence

Screenshots are stored in `/evidence`:

- [ ] PowerShell logging enabled (registry/GPO)
- [ ] Wazuh agent active in dashboard
- [ ] Raw 4104/Sysmon event in archives
- [ ] Alert for rule 100600
- [ ] Alert for rule 100610
- [ ] MITRE ATT&CK view in dashboard

## Troubleshooting

| Problem | Fix |
|---|---|
| No PowerShell events in Wazuh | Confirm `<localfile>` channel names match exactly; restart `WazuhSvc` |
| Events arrive but no alert | Test the raw event in `wazuh-logtest`; check field names and regex |
| Decoder field-cap error | Increase `analysisd.decoder_order_size` (e.g. `1024`) in `local_internal_options.conf` |
| Rule file errors on restart | Check `/var/ossec/logs/ossec.log` for XML syntax errors |

## Repository Structure

```
.
├── README.md
├── rules/
│   └── local_rules.xml
├── config/
│   └── ossec-agent-snippet.xml
├── scripts/
│   └── enable-powershell-logging.ps1
└── evidence/
    └── screenshots/
```

## MITRE ATT&CK Coverage

- **T1059.001** – Command and Scripting Interpreter: PowerShell
- **T1564.003** – Hide Artifacts: Hidden Window
- **T1033** – System Owner/User Discovery
- **T1082** – System Information Discovery

## Disclaimer

For educational use in an isolated home lab only. Do not run the test commands on systems you don't own or have permission to test.

## Author

**Hope Imomoh**, SOC Analyst Trainee, Abuja, Nigeria
[GitHub](https://github.com/) · [LinkedIn](https://linkedin.com/)
