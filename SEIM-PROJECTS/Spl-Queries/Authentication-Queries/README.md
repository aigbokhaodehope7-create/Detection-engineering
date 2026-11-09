
# SMB Brute Force Detection Lab (Wazuh)

Simulating a credential brute-force attack against SMB on a domain-joined Windows Server 2019 host, and validating detection coverage in Wazuh — including a real Windows audit-policy logging gap discovered and fixed mid-lab.

![Platform](https://img.shields.io/badge/SIEM-Wazuh-blue)
![Target](https://img.shields.io/badge/Target-Windows%20Server%202019-0078D6)
![Domain](https://img.shields.io/badge/Domain-HopeLabs.Local-informational)
![MITRE](https://img.shields.io/badge/MITRE-T1110.001-red)

> Incident ID: **LAB-2026-002**

---

## Objective

Simulate a brute-force credential attack against an SMB service on a domain-joined Windows Server 2019 host, using tools on Kali Linux, and validate that the attack is actually detected end-to-end in Wazuh.

## Lab Topology

| Role | Host | IP | OS |
|---|---|---|---|
| Attacker | Kali Linux | `192.168.56.102` | Kali Rolling |
| Target | DESKTOP-T6T1N2V | `192.168.56.116` | Windows Server 2019 (Build 19041), domain: `HopeLabs.Local` |
| SIEM | Wazuh Manager | `192.168.56.101` | Ubuntu |

Target account: `HR-STAFF1`

```
 Kali (attacker) ── SMB/445 ──▶ Windows Server 2019 (DESKTOP-T6T1N2V, domain-joined)
                                    │  Security log: 4624 / 4625 (logonType 3, NTLM)
                                    └── Wazuh agent ───▶ Wazuh Manager ──▶ Alerts
```

## Prerequisites

- Kali Linux with `smbclient` and `crackmapexec` installed
- Windows Server 2019 target, domain-joined to `HopeLabs.Local`, Wazuh agent active
- A test domain account (e.g. `HR-STAFF1`) with a password in your wordlist
- A small password list, e.g. `passwords.txt`, with the correct password included

---

## Step 1: Initial Enumeration

Confirm SMB is reachable and the account is valid before attacking:

```bash
smbclient -L //192.168.56.116 -U 'HopeLabs\HR-STAFF1'
```

Expected result: standard shares (`ADMIN$`, `C$`, `IPC$`, `Users`) returned, confirming SMB auth is functioning. An `NT_STATUS_RESOURCE_NAME_NOT_FOUND` on the SMB1 workgroup-listing step is expected — SMB1 is disabled by default on modern Windows and is not an auth or connectivity problem.

## Step 2: Brute Force Attempt — Hydra (fails, by design)

```bash
hydra -l HR-STAFF1 -p passwords.txt -t 1 192.168.56.116 smb
```

Result: `[ERROR] invalid reply from target` — reproducible across `smb`, `smb2`, and various `-s`/`-m` flag combinations.

**Root cause:** Hydra's SMB modules rely on an older SMB1/NTLM implementation that frequently fails to complete the handshake against SMB2/3-only hosts such as a default-hardened Server 2019 box. This is a protocol-compatibility limitation, not a credential or syntax issue.

## Step 3: Pivot to CrackMapExec

```bash
crackmapexec smb 192.168.56.116 -u HR-STAFF1 -p passwords.txt
```

Initial run returns host fingerprint info, then times out on auth (`NETBIOS connection with the remote host timed out`). ICMP connectivity is clean, isolating the fault to the auth phase, not the network path.

Re-run with the domain explicitly specified resolves it:

```bash
crackmapexec smb 192.168.56.116 -u HR-STAFF1 -p passwords.txt -d HopeLabs.Local
```

```
[-] HopeLabs.Local\HR-STAFF1:msfadmin    STATUS_LOGON_FAILURE
[-] HopeLabs.Local\HR-STAFF1:kali        STATUS_LOGON_FAILURE
[-] HopeLabs.Local\HR-STAFF1:vagrant     STATUS_LOGON_FAILURE
[-] HopeLabs.Local\HR-STAFF1:ubuntu      STATUS_LOGON_FAILURE
[+] HopeLabs.Local\HR-STAFF1:Hope199872
```

**Root cause of the timeout:** CrackMapExec's SMB auth phase behaves unreliably against a domain-joined target when no domain (`-d`) is specified, even though initial protocol negotiation succeeds without it.

## Step 4: Detection Gap Identified

Looking for the corresponding events in Wazuh surfaced a second, unrelated issue: **no Windows Security audit events were being generated at all.**

```powershell
auditpol /get /category:"Logon/Logoff"
```

showed every Logon/Logoff subcategory set to `No Auditing`. The Wazuh agent (`wazuhsvc`) was running and connected — with local audit policy disabled, Event IDs 4624/4625 simply never existed on the host for the agent to forward. This was a Windows-side logging gap, not a Wazuh ingestion or agent-connectivity problem.

**Remediation:**

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
```

Verify with:

```powershell
auditpol /get /category:"Logon/Logoff"
```

Confirm both subcategories now show `Success and Failure`.

## Step 5: Custom Detection Rules

Add to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh manager:

```xml
<group name="windows,authentication,smb,bruteforce,">

  <rule id="100100" level="10">
    <if_sid>60122</if_sid>
    <field name="win.eventdata.logonType">3</field>
    <description>Windows Failed Login Detected</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>

  <rule id="100101" level="12" frequency="8" timeframe="120">
    <if_matched_sid>100100</if_matched_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>Multiple Windows Failed Logons Detected – Possible Brute Force</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>

</group>
```

Validate and apply:

```bash
sudo /var/ossec/bin/wazuh-logtest      # paste a sample 4625 event to test
sudo systemctl restart wazuh-manager
```

## Step 6: Re-run the Attack and Verify Detection

With audit policy corrected, re-run the CrackMapExec attack from Step 3. This generates Event ID 4625 (failed logon) entries, correctly ingested and correlated by Wazuh.

Sample alert detail:

```
data.win.system.eventID:              4625
data.win.system.channel:              Security
data.win.system.computer:             DESKTOP-T6T1N2V.HopeLabs.Local
data.win.eventdata.targetUserName:    HR-STAFF1
data.win.eventdata.targetDomainName:  HopeLabs.Local
data.win.eventdata.ipAddress:         192.168.56.102   (Kali attacker)
data.win.eventdata.ipPort:            33128
data.win.eventdata.authenticationPackageName: NTLM
data.win.eventdata.logonProcessName:  NtLmSsp
data.win.eventdata.logonType:         3   (network logon — consistent with SMB)
```

`logonType: 3` and the `NtLmSsp`/NTLM authentication package correctly reflect an SMB-based remote authentication attempt rather than an interactive console logon. The source IP ties every failed attempt back to the Kali attacker host, and the level-12 correlation rule (100101) confirms the SIEM distinguished a repeated-failure pattern from an isolated failed login.

Check in the dashboard under **Threat Hunting → Events**, filter:

```
rule.id: (100100 OR 100101)
```

Or on the manager:

```bash
sudo grep -E '"id":"(100100|100101)"' /var/ossec/logs/alerts/alerts.json | tail -n 5
```

This closes the gap from Step 4: once local audit policy was corrected, the existing Wazuh pipeline (agent → manager → custom rules) required no further changes to detect the attack.

## Detection Summary

| Rule ID | Level | Behavior | MITRE ATT&CK |
|---|---|---|---|
| 100100 | 10 | Single failed SMB/network logon (type 3) | T1110.001 |
| 100101 | 12 | 8+ failed logons from same source in 2 minutes | T1110.001 |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Discovery | Network Share Discovery | T1135 |
| Defense Evasion (target-side finding) | Impair Defenses: Disable Windows Event Logging | T1562.002 |

## Key Findings & Lessons Learned

- **Tool selection matters as much as technique.** Hydra's SMB module is unreliable against SMB2/3-only hosts; CrackMapExec (or its maintained fork, NetExec) is the more appropriate tool for modern Windows targets.
- **Domain context is required for reliable auth against domain-joined hosts.** Omitting `-d <domain>` caused silent timeouts rather than clear auth failures, which can be misleading during troubleshooting.
- **A working attack path is only half the exercise.** Discovering that audit policy was fully disabled on the target — meaning the brute-force attempts left *no* security event trail — was itself a meaningful finding, directly relevant to real-world SOC work: attackers benefit from exactly this kind of default logging gap.
- **Detection validation should be built into every offensive lab exercise**, not treated as an afterthought — the absence of alerts is only useful information if you can distinguish "SIEM didn't detect it" from "the event was never generated."

## False Positives & Tuning

| Cause | Tuning |
|---|---|
| User mistyping a password repeatedly | Raise the frequency threshold or require distinct target accounts |
| Service/scheduled task retrying a stale credential | Allowlist the known service account and source host |
| Legitimate admin scanning SMB shares across the domain | Allowlist known management/scanner IPs |

## Evidence

Screenshots are stored in `/evidence`:

- [ ] `smbclient` share listing confirming SMB auth works
- [ ] Hydra failure output (protocol incompatibility)
- [ ] CrackMapExec timeout without `-d`, then success with `-d`
- [ ] `auditpol /get` showing `No Auditing` (the gap)
- [ ] `auditpol /get` showing `Success and Failure` (after fix)
- [ ] Wazuh alert for rule 100100
- [ ] Wazuh alert for rule 100101
- [ ] MITRE ATT&CK view in the Wazuh dashboard

## Next Steps

- Build a Wazuh Active Response to automatically disable or firewall-block an account after N failed logons within a defined window.
- Extend the correlation rule to cross-reference the source IP against a known-attacker watchlist.
- Add a Sigma rule version of the 100101 correlation logic for portability to other SIEM backends.

## Repository Structure

```
.
├── README_SMB_Brute_Force.md
├── rules/
│   └── local_rules.xml
├── reports/
│   └── LAB-2026-002.pdf
└── evidence/
    └── screenshots/
```

## Disclaimer

For educational use in an isolated home lab only. Do not run these tools against systems you don't own or have permission to test.

## Author

**Hope Imomoh**, SOC Analyst Trainee, Abuja, Nigeria
[GitHub](https://github.com/) · [LinkedIn](https://linkedin.com/)
