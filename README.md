
# Detection-engineering

A collection of detection rules — Sigma, YARA, and Wazuh today, Suricata and Snort coming next — written to identify malicious behavior across the host, log, file, and network layers. Rules are organized by detection category and grounded in real home-lab attack simulations, not written in a vacuum.

![Rules](https://img.shields.io/badge/Sigma-rules-blueviolet)
![Rules](https://img.shields.io/badge/YARA-rules-black)
![Rules](https://img.shields.io/badge/Wazuh-rules-blue)
![Rules](https://img.shields.io/badge/Suricata-planned-orange)
![Rules](https://img.shields.io/badge/Snort-planned-darkred)

---

## About This Repo

Every rule here was written for a reason: a lab exercise, a simulated attack, or a forensic challenge. Rules aren't just dropped in — each category is documented with the logic behind it, and where possible, validated firing live in a SIEM. The goal is to show the full detection engineering loop, not just finished rule files:

**Idea → write rule → test against sample data → validate in a live SIEM → document → tune for false positives**

This repo tracks detection logic across multiple layers of the stack:

- **Sigma** — log-based, SIEM-agnostic detections (currently Windows event logs)
- **YARA** — file-based detections for malware, C2 artifacts, ransomware, trojans, and suspicious files
- **Wazuh** — host-based custom correlation rules, validated end-to-end in a live home-lab SIEM
- **Suricata / Snort** *(planned)* — network-layer IDS/IPS detections for the same attack behaviors, giving each technique coverage at both the host/log layer and the wire

## Repository Structure

```
.
├── README.md
├── Sigma-Rules/
│   └── Windows-Rules/
│       ├── README.md
│       ├── account_created.yml
│       ├── account_enabled.yml
│       ├── account_modified.yml
│       ├── brute_force_login.yml
│       ├── powershell_download_activity.yml
│       ├── priviledge_escalation.yml
│       ├── service_configuration_change.yml
│       ├── suspicious_encoded_command.yml
│       ├── suspicious_hidden_powershell.yml
│       ├── suspicious_mshta_execution.yml
│       ├── suspicious_powershell.yml
│       ├── suspicious_process_injections.yml
│       ├── suspicious_registry_modification.yml
│       ├── suspicious_regsvr32_execution.yml
│       ├── suspicious_rundll32_execution.yml
│       ├── suspicious_schedule_task.yml
│       └── suspicious_service_installation.yml
├── YARA-Rules/
│   ├── C2-Detection/
│   │   ├── README.md
│   │   ├── c2_indicator.yar
│   │   └── c2_indicators.yar
│   ├── Malware-Detection/
│   │   ├── README.md
│   │   └── generic_malware.yar
│   ├── PowerShell-Detection/
│   │   ├── README.md
│   │   └── suspicious_powershell.yar
│   ├── Ransomware-Detection/
│   │   ├── README.md
│   │   └── ransomware_indicators.yar
│   ├── Suspicious-Files/
│   │   ├── README.md
│   │   └── suspicious_file_patterns.yar
│   └── Trojan-Detection/
│       ├── README.md
│       └── trojan_indicators.yar
├── Wazuh-Rules/
│   ├── README.md
│   ├── Account-Compromise-Detection/
│   │   └── README.md          # rule 100500
│   ├── PowerShell-Detection/
│   │   └── README.md          # rules 100600, 100610
│   ├── SMB-Brute-Force-Detection/
│   │   └── README.md          # rules 100100, 100101
│   └── RDP-Brute-Force-Detection/
│       └── README.md          # built-in rules 60122/60204/60106
├── Suricata-Rules/             # planned
└── Snort-Rules/                # planned
```

## Rule Index

### Sigma Rules (`Sigma-Rules/Windows-Rules/`)

| Rule | Category | Status |
|---|---|---|
| `account_created.yml` | Account management | ⏳ Needs MITRE/FP docs |
| `account_enabled.yml` | Account management | ⏳ Needs MITRE/FP docs |
| `account_modified.yml` | Account management | ⏳ Needs MITRE/FP docs |
| `brute_force_login.yml` | Credential access | ⏳ Needs MITRE/FP docs |
| `powershell_download_activity.yml` | Execution / download | ⏳ Needs MITRE/FP docs |
| `priviledge_escalation.yml` | Privilege escalation | ⏳ Needs MITRE/FP docs |
| `service_configuration_change.yml` | Persistence | ⏳ Needs MITRE/FP docs |
| `suspicious_encoded_command.yml` | Execution (PowerShell) | ⏳ Needs MITRE/FP docs |
| `suspicious_hidden_powershell.yml` | Defense evasion | ⏳ Needs MITRE/FP docs |
| `suspicious_mshta_execution.yml` | Execution (LOLBin) | ⏳ Needs MITRE/FP docs |
| `suspicious_powershell.yml` | Execution | ⏳ Needs MITRE/FP docs |
| `suspicious_process_injections.yml` | Defense evasion | ⏳ Needs MITRE/FP docs |
| `suspicious_registry_modification.yml` | Persistence | ⏳ Needs MITRE/FP docs |
| `suspicious_regsvr32_execution.yml` | Execution (LOLBin) | ⏳ Needs MITRE/FP docs |
| `suspicious_rundll32_execution.yml` | Execution (LOLBin) | ⏳ Needs MITRE/FP docs |
| `suspicious_schedule_task.yml` | Persistence | ⏳ Needs MITRE/FP docs |
| `suspicious_service_installation.yml` | Persistence | ⏳ Needs MITRE/FP docs |

### YARA Rules (`YARA-Rules/`)

| Rule | Category | Status |
|---|---|---|
| `C2-Detection/c2_indicator.yar` | Command and Control | ⏳ Needs MITRE/FP docs |
| `C2-Detection/c2_indicators.yar` | Command and Control | ⏳ Needs MITRE/FP docs |
| `Malware-Detection/generic_malware.yar` | General malware | ⏳ Needs MITRE/FP docs |
| `PowerShell-Detection/suspicious_powershell.yar` | Execution | ⏳ Needs MITRE/FP docs |
| `Ransomware-Detection/ransomware_indicators.yar` | Ransomware | ⏳ Needs MITRE/FP docs |
| `Suspicious-Files/suspicious_file_patterns.yar` | General suspicious files | ⏳ Needs MITRE/FP docs |
| `Trojan-Detection/trojan_indicators.yar` | Trojan | ⏳ Needs MITRE/FP docs |

### Wazuh Rules (`Wazuh-Rules/`)

| Rule | Project | MITRE ATT&CK | Status |
|---|---|---|---|
| 100500 | Account Compromise Detection (Domain Admins addition) | T1098, T1078.002 | ✅ Validated |
| 100600 | PowerShell Detection — hidden window | T1059.001, T1564.003 | ✅ Validated |
| 100610 | PowerShell Detection — encoded command → whoami/hostname | T1059.001, T1033, T1082 | ✅ Validated |
| 100100 | SMB Brute Force Detection — failed logon | T1110.001 | ✅ Validated |
| 100101 | SMB Brute Force Detection — correlated brute force | T1110.001 | ✅ Validated |
| 60122 / 60204 / 60106 (built-in) | RDP Brute Force Detection | T1110, T1110.001, T1078 | 🧪 Partial — custom ID unconfirmed |

**Status key:** ✅ Validated live (SIEM/sample) · 🧪 Tested against sample data, or partially documented · ⏳ Written, not yet documented/tested

> As rules get tested and documented, update their status here and link to the writeup in the rule's own folder README.

## Rule Documentation Format

Each category folder has its own `README.md` explaining what that category detects and why. Rules include, either inline as comments or in the folder README:

- **What it detects** — plain-language description
- **Why this logic** — reasoning behind the detection, not just the pattern
- **MITRE ATT&CK mapping** — tactic and technique ID
- **Known false positives** — what legitimate activity could trigger it
- **Validation evidence** — sample log/file that triggers it, and where it was tested (home lab report, if any)

## Testing

Rules are validated two ways:

1. **Static/sample testing** — sample log lines, PCAPs, or binaries run against the rule (`sigma convert`, `yara` CLI, `wazuh-logtest`) to confirm it matches intended data and not benign data.
2. **Live validation** — rule deployed in the home SIEM lab and fired against a real simulated attack. See linked lab reports and [aigbokhaodehope7-create/SOC-Home-Lab-Evidence](https://github.com/aigbokhaodehope7-create/SOC-Home-Lab-Evidence) for screenshots and alert JSON.

## Roadmap

- [ ] Add `Suricata-Rules/` — network-layer rules mirroring existing Sigma/Wazuh detections (brute force, C2 beaconing, suspicious downloads)
- [ ] Add `Snort-Rules/` — same coverage as Suricata, for environments standardized on Snort
- [ ] Confirm or add the custom Wazuh correlation rule ID for the RDP Brute Force lab
- [ ] Backfill MITRE ATT&CK mapping and false-positive notes for every existing Sigma and YARA rule
- [ ] Resolve the `C2-Detection/` duplicate (`c2_indicator.yar` vs `c2_indicators.yar`)
- [ ] Add a `tests/` folder with sample logs/PCAPs/files used to validate each rule
- [ ] Add CI (GitHub Actions) to lint Sigma YAML, validate YARA syntax, and check Wazuh rule XML on every push

## Related Repositories

- [aigbokhaodehope7-create/SOC-Home-Lab-Evidence](https://github.com/aigbokhaodehope7-create/SOC-Home-Lab-Evidence) — lab build evidence, screenshots, live detection validation

## Author

**Hope Imomoh**, SOC Analyst Trainee, Abuja, Nigeria
[GitHub](https://github.com/aigbokhaodehope7-create) · [LinkedIn](https://linkedin.com/)
