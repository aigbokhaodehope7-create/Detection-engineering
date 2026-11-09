# Suricata Rules

Network-layer IDS rules written to mirror the host/log-layer detections already built in `Sigma-Rules/` and `Wazuh-Rules/`. Where a Wazuh or Sigma rule catches an attack in Windows logs, the matching Suricata rule here is meant to catch the same attack on the wire.

## SID Convention

Suricata requires custom rule SIDs in the `1,000,000+` range (anything below is reserved for official/community rulesets). This repo groups SIDs by project, matching the Wazuh-Rules ID convention:

| SID Range | Reserved For |
|---|---|
| 1000100–1000199 | SMB authentication / brute force |
| 1000600–1000699 | PowerShell / download activity |
| 1000700–1000799 | RDP authentication / brute force |
| 1000800–1000899 | Phishing (payload delivery, credential harvesting, C2) |

## Projects Covered

| Folder | Project | SIDs | Status |
|---|---|---|---|
| `SMB-Brute-Force-Detection/` | SMB Brute Force Lab (LAB-2026-002) | 1000100, 1000101 | 🧪 Written, needs PCAP validation |
| `RDP-Brute-Force-Detection/` | RDP Brute Force Lab (INC-2026-001) | 1000700 | 🧪 Written, needs PCAP validation |
| `PowerShell-Detection/` | PowerShell Detection Lab | 1000600 | 🧪 Written, needs PCAP validation |
| `Phishing-Detection/` | Phishing Detection Lab | 1000800, 1000801 | 🧪 Written, needs PCAP validation |

**Status key:** ✅ Validated against a live/replayed PCAP · 🧪 Written, not yet tested · ⏳ Draft

## How These Rules Are Deployed

Each folder contains one `.rules` file. Combine them into Suricata's local ruleset:

```bash
sudo cp *.rules /etc/suricata/rules/
```

Reference them from `suricata.yaml` under `rule-files:`, then test syntax and reload:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
```

Validate a rule against a sample PCAP before trusting it live:

```bash
sudo suricata -r sample.pcap -S /etc/suricata/rules/<file>.rules -k none -l /tmp/suricata-test
cat /tmp/suricata-test/fast.log
```

## Related

- [aigbokhaodehope7-create/SOC-Home-Lab-Evidence](https://github.com/aigbokhaodehope7-create/SOC-Home-Lab-Evidence) — full lab builds, screenshots, and alert evidence
- `Wazuh-Rules/` — the host/log-layer counterpart to these network rules
-
