# Wazuh Rules

Custom Wazuh detection rules written and validated across home-lab projects. Each subfolder holds the rule XML for one detection scenario, pulled from `local_rules.xml` on the lab's Wazuh manager, along with a README explaining the logic, MITRE ATT&CK mapping, and validation evidence.

## Rule ID Convention

All custom rules use the `100000+` range, as required by Wazuh for local/custom rules (IDs below 100000 are reserved for Wazuh's built-in ruleset). Rules are grouped loosely by the order they were added:

| ID Range | Reserved For |
|---|---|
| 100100–100199 | SMB authentication / brute force |
| 100500–100599 | Account & privilege management |
| 100600–100699 | PowerShell execution / defense evasion |
| 100700–100799 | RDP authentication / brute force |

## Projects Covered

| Folder | Project | Rule IDs | Status |
|---|---|---|---|
| `Account-Compromise-Detection/` | Domain Admin group modification | 100500 | ✅ Validated |
| `PowerShell-Detection/` | PowerShell Detection Lab | 100600, 100610 | ✅ Validated |
| `SMB-Brute-Force-Detection/` | SMB Brute Force Lab (LAB-2026-002) | 100100, 100101 | ✅ Validated |
| `RDP-Brute-Force-Detection/` | RDP Brute Force Lab (INC-2026-001) | built-in (60122, 60204, 60106) + custom — *ID to confirm* | 🧪 Partial |

**Status key:** ✅ Validated live in the home lab · 🧪 Partial / needs confirmation · ⏳ Draft, not yet tested

> `RDP-Brute-Force-Detection/` currently documents the built-in Wazuh rules the lab relied on (60122, 60204, 60106). If a custom correlation rule was added for that lab beyond the built-ins, add its real ID and XML here — I don't have that exact rule number on file.

## How These Rules Are Deployed

All custom rules live in a single `local_rules.xml` on the Wazuh manager (`/var/ossec/etc/rules/local_rules.xml`). Each folder here contains the `<group>` block relevant to that project — combine them into your manager's `local_rules.xml` and restart the service:

```bash
sudo systemctl restart wazuh-manager
```

Validate a rule before deploying with:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

## Related

- [aigbokhaodehope7-create/SOC-Home-Lab-Evidence](https://github.com/aigbokhaodehope7-create/SOC-Home-Lab-Evidence) — full lab builds, screenshots, and alert evidence for each rule below
-
