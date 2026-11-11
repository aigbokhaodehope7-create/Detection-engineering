# Persistence Detection Lab (Day 8)

Detecting hidden Windows start-up tricks with **Sysmon**, **Wazuh** and **Splunk**, plus a companion **YARA** rule set.

**Author:** Aigbokhaode Hope Imomoh, SOC Analyst Trainee, Abuja, Nigeria
**Lab date:** 9 November 2026 | **Report:** v1.0, 10 November 2026
**Classification:** Portfolio / training project. Lab-only, harmless test payloads.

---

## Overview

Attackers who break into a computer often set up *persistence* so they can come back after a restart or logout. This lab creates three harmless examples in an isolated virtual lab, detects each one, traces who created it, maps it to MITRE ATT&CK, writes detection rules, then removes everything and proves the clean-up.

| Technique | Test item | MITRE ATT&CK | Wazuh rule | Result |
|---|---|---|---|---|
| Scheduled task | `WindowsUpdateCheck` (SYSTEM, at logon) | T1053.005 | 100620 (level 10) | Verified |
| Windows service | `UpdSvc` (LocalSystem, auto start) | T1543.003 | 100621 (level 12) | Verified |
| Registry Run key (reg.exe) | `Updater` | T1547.001 | 92302, overwritten 6 to 12 | Verified after tuning |
| Registry Run key (PowerShell) | `Updater3` | T1547.001 | 100622 (level 12) | Verified |

All payloads were harmless (`whoami`, `calc.exe`).

## Lab environment

- **Windows 10 endpoint (victim):** Sysmon, Wazuh agent, domain `HopeLabs.Local`
- **Ubuntu server:** Wazuh manager and dashboard, Splunk Enterprise 9.4.2
- Everything runs in VirtualBox on a private network, not connected to any real organisation.

```
Windows 10 (Sysmon, Security/System logs, Wazuh agent)
        |                                  |
        v                                  v
 Wazuh manager (rules -> alerts)     Splunk (raw events for searching)
        \                                  /
         \---------- Analyst (browser) ---/
```

## Repository contents

| File | Purpose |
|---|---|
| `Persistence_Detection_Lab_Report.pdf` | Full 83-page lab report with commands, screenshots and analysis |
| `persistence_detection_lab.yar` | YARA rules for scripts, task XML, `.reg` exports and lab IOCs |
| `local_rules.xml` (rule group) | The four Wazuh rules, listed below and in Appendix A of the report |
| `README.md` | This file |

> Adjust the file names above to match what you actually upload.

## Wazuh rules (final)

Installed in `/var/ossec/etc/rules/local_rules.xml` on the Ubuntu server.

```xml
<group name="persistence,windows,">
  <rule id="100620" level="10">
    <if_sid>60228</if_sid>
    <description>Scheduled task created: $(win.eventdata.taskName)</description>
    <mitre><id>T1053.005</id></mitre>
  </rule>
  <rule id="100621" level="12">
    <if_sid>61138</if_sid>
    <field name="win.eventdata.imagePath" type="pcre2">(?i)cmd\.exe|powershell|Users.Public|.Temp.</field>
    <description>Suspicious service installed: $(win.eventdata.serviceName)</description>
    <mitre><id>T1543.003</id></mitre>
  </rule>
  <rule id="92302" level="12" overwrite="yes">
    <if_sid>92300</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)reg\.exe</field>
    <options>no_full_log</options>
    <description>Run key persistence via reg.exe (escalated from level 6)</description>
    <mitre><id>T1547.001</id></mitre>
  </rule>
  <rule id="100622" level="12">
    <if_sid>92300</if_sid>
    <field name="win.eventdata.image" type="pcre2" negate="yes">(?i)reg\.exe|msedge\.exe|OneDrive\.exe|CompatTelRunner</field>
    <description>Run key persistence by $(win.eventdata.image)</description>
    <mitre><id>T1547.001</id></mitre>
  </rule>
</group>
```

Test before restarting, and keep a backup:

```bash
sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

## YARA rules

YARA scans **files and memory**, not live event logs. Live detection stays in Wazuh; YARA covers the evidence side (scripts, exports, memory dumps).

| Rule | Catches |
|---|---|
| `Persistence_Script_Creates_Autostart` | Scripts that create a task, service or Run key (two techniques in one file, or `/ru SYSTEM` with `/sc onlogon`) |
| `Persistence_Task_XML_SYSTEM_Logon` | Exported task XML: logon trigger, SYSTEM, suspicious action |
| `Persistence_RunKey_Export_Suspicious` | `.reg` exports with a Run value launching cmd, PowerShell, calc or Public/Temp paths |
| `Persistence_Service_Binpath_Suspicious` | Services whose `ImagePath` is cmd or PowerShell, or matching 7045 exports |
| `Persistence_Lab_IOC_Names` | Lab-only names and the logon ID, for finding leftovers or evidence copies |

```bash
yara -w persistence_detection_lab.yar        # check that it compiles
yara -r persistence_detection_lab.yar <folder_or_file>
```

## Key lessons

- **A missing setting hides evidence.** The first task creation produced no Security event 4698 because the "Other Object Access Events" audit policy was off.
- **Built-in rules can shadow your own.** My first Run key rule never fired because Wazuh's built-in rule 92302 matched first. Fix: overwrite 92302 and rebuild 100622 on parent 92300.
- **Different tools see different things.** Wazuh gives fast labelled alerts; Splunk keeps raw events, failed attempts and exact command lines.
- **One session explains everything.** Splunk tied every command to PowerShell PID 6324 and logon ID `0x180B06`.

## Limitations (honest results)

- One host, one administrator account, harmless commands only.
- Not tested: Startup folder, RunOnce, machine-wide (HKLM) Run keys, WMI, non-admin attackers, real malware, false-positive rates.
- The lab verified that items were *created*, not that they *executed*.
- Why rule 100623 failed is unconfirmed.
- PowerShell command logging is unverified (the Splunk search used lower-case `or`, so the zero results prove nothing).
- The YARA rules are a companion to the lab and were not part of the original tested evidence.
- Exact Sysmon and Wazuh versions were not captured.

## Safety

- Run only in an isolated lab. Never practise persistence techniques on a real or shared computer.
- Test items use obvious names (`WindowsUpdateCheck`, `UpdSvc`, `Updater`) so they are easy to find and delete.
- Clean-up is verified with query commands, not assumed.

```powershell
schtasks /delete /tn "WindowsUpdateCheck" /f
sc.exe delete UpdSvc
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /f
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater3 /f
```

## Next steps

1. Repeat the lab with commands typed from memory.
2. Add rules for the Startup folder and HKLM Run keys.
3. Enable and verify PowerShell Script Block Logging (event 4104).
4. Investigate why rule 100623 failed.
5. Build a Splunk alert for event 4698.

## References

- MITRE ATT&CK: [T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [Wazuh documentation](https://documentation.wazuh.com/)
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [Splunk Search Reference](https://docs.splunk.com/)

## Disclaimer

For education and authorised testing only. Machine names, IP addresses and SIDs in the report belong to a private lab; replace them before sharing publicly.
