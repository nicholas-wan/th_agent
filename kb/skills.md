# Platform Attack Skills Repository

Platform-specific detection skills tied to particular technology platforms or log sources. Each skill encodes detection patterns, SPL templates, and FP exclusions for a specific platform that may not yet be fully onboarded into the environment.

`skillType` values:
- `domain` — Platform or log-source specific skill

To add a new skill, copy any section below, paste it before the last `---`, and fill in the fields. Required fields: `type`, `category`, `category-label`, `ttps`, `author`.

---

## SK-045 — VMware vCenter Lateral Movement

> type: domain | category: lateral-movement | category-label: Lateral Movement | ttps: T1078.001, T1550.003
> author: rmendez | version: v1.2 | updated: 2026-05-14 | agents: tradecraft, detection

VMware vCenter SSO token abuse and vSphere API lateral movement. Covers service-to-service auth anomalies, management plane enumeration, and host-jump via vMotion. Particularly useful for environments with mixed ESXi/vCenter topologies where standard endpoint telemetry is sparse.

### Patterns
- vCenter SSO authentication events from non-standard service accounts outside VI-Admins OU
- vSphere API calls (vim.vm.guest.ProcessManager) outside approved maintenance windows
- Host-to-host connections on port 902/903 not correlated to a scheduled vMotion task
- PowerCLI execution on endpoints that are not in the VI-Admins or VMware-Ops groups

### SPL
```spl
index=vcenter sourcetype=vmware:vcenter:event
| search EventType=UserLoginSessionEvent
| where NOT match(userName, "^svc-vi|^svc-vcenter|^vSphere")
| stats count by userName, ipAddress, datacenter
```

### Exclusions
- Scheduled vMotion tasks — validate against CMDB change-mgmt window
- svc-backup account during nightly backup window 01:00–04:00
- VMware Tools update process (vmtoolsd.exe) on managed VMs

### Attack Paths
- T1550.001 | Use Alt Auth: App Access Token | high | vSphere SSO tokens replayed to authenticate to additional VMs and management interfaces without re-authentication
- T1021.004 | Remote Services: SSH | medium | SSH to ESXi hosts directly using credentials harvested via vCenter API or management plane
- T1059.006 | Command & Scripting: Python | medium | PyVmomi library used to enumerate VM inventory, extract guest credentials, and pivot via vSphere API calls

---

## SK-031 — Firewall Anomaly — East-West Lateral Spread

> type: domain | category: lateral-movement | category-label: Lateral Movement | ttps: T1021.001, T1021.002, T1570
> author: akowalski | version: v1.0 | updated: 2026-03-11 | agents: tradecraft, dataeng

Identifies abnormal east-west firewall flows indicative of lateral movement — new RDP/SMB paths between previously unconnected segments or port scans from workstation-class assets. Requires firewall log source onboarding into Splunk (index=firewall).

### Patterns
- New RDP (3389) accept flows between workstation subnets with no prior 30d history
- SMB (445) accept from non-server sources within Corp-Workstations (10.10.x.x/16)
- Port sweep across >5 hosts from a single workstation-class asset within 120s
- ICMP echo sweep originating from a CMDB tier=3 (workstation) asset

### SPL
```spl
index=firewall action=accept dest_port IN (445, 3389, 5985)
| where src_zone == dest_zone AND src_zone="Corp-Workstations"
| stats dc(dest_ip) as targets by src_ip
| where targets > 3
```

### Exclusions
- IT Support VLAN (10.10.50.0/24) — helpdesk RDP is expected and baselined
- SCCM server (10.0.5.20) — SMB to all workstations during patch cycles

### Attack Paths
- T1003.001 | LSASS Memory | high | Credential access on newly reached host to harvest hashes for the next lateral hop
- T1570 | Lateral Tool Transfer | high | Attacker tooling deployed via SMB admin shares once lateral path is established
- T1049 | System Network Connections Discovery | medium | Network enumeration from beachhead host to map additional targets

---

## SK-062 — SolarWinds Orion — Compromise & Lateral Movement Indicators

> type: domain | category: lateral-movement | category-label: Lateral Movement | ttps: T1195.002, T1078.003, T1556.006, T1071.001, T1036.005
> author: jsmith | version: v1.0 | updated: 2026-05-28 | agents: tradecraft, detection

Detection patterns for SolarWinds Orion platform compromise — covering supply chain DLL abuse (SUNBURST pattern), Orion API auth bypass, suspicious Orion service account activity, and SAML token forgery originating from the Orion host. Requires SolarWinds Orion event logs and Windows telemetry from the Orion server forwarded to Splunk (index=solarwinds, index=sysmon host=ORION-*).

### Patterns
- Orion process (SolarWinds.BusinessLayerHost.exe) making outbound HTTPS to non-SolarWinds IPs — SUNBURST beacon pattern
- DLL load from SolarWinds install directory with unsigned or recently modified timestamp outside a patch window
- Orion service account (svc-orion) authenticating to hosts outside the Orion-approved polling scope defined in CMDB
- SAML assertion issued from ADFS where the source request originated on the Orion server IP — golden SAML indicator
- SolarWinds.Orion.Core.BusinessLayer.dll file hash mismatch against vendor-published hash list
- Orion DB account (svc-orion-db) executing non-SELECT SQL statements outside scheduled maintenance

### SPL
```spl
index=sysmon host="ORION-*" EventCode=3
| where match(Image, "(?i)SolarWinds")
| where NOT match(dest_ip, "^(13\.56|34\.198|52\.|54\.)")
| where NOT match(dest_ip, "^10\.|^172\.|^192\.168\.")
| stats count by Image, dest_ip, dest_port
| where count >= 1
| sort - count
```

### Exclusions
- SolarWinds license check to api.solarwinds.com (146.148.x.x) — outbound HTTPS expected daily
- Orion polling engine connections to monitored devices — validate against Orion-monitored-nodes lookup
- THWACK community portal traffic (thwack.com) from Orion admin workstations — not from the Orion server itself

### Attack Paths
- T1556.006 | Modify Auth Process: SAML | critical | SUNBURST-style compromise of the Orion server grants access to the ADFS signing certificate — enabling forged SAML tokens that bypass MFA and grant access to any federated service (M365, Azure, on-prem apps)
- T1078.003 | Valid Accounts: Local Accounts | high | The Orion service account has broad read access across the network for monitoring — credential theft gives attacker a pre-authorised lateral movement path to all monitored devices
- T1071.001 | Application Layer Protocol: Web | high | Compromised Orion beacons to C2 via HTTPS blending with legitimate SolarWinds telemetry — outbound from the monitoring server is rarely inspected by egress controls

---

## SK-061 — Ivanti Connect Secure — Exploitation & Post-Auth Abuse

> type: domain | category: lateral-movement | category-label: Lateral Movement | ttps: T1190, T1505.003, T1078.002, T1027
> author: rmendez | version: v1.0 | updated: 2026-05-28 | agents: tradecraft, detection

Detection patterns for Ivanti Connect Secure (ICS) VPN exploitation — covering auth bypass (CVE-2023-46805, CVE-2024-21887), web shell staging in the appliance filesystem, credential theft via debug log exposure, and anomalous session behaviour post-compromise. Requires Ivanti syslog forwarded to Splunk (index=ivanti).

### Patterns
- REST API auth bypass: requests to /api/v1/totp/user-backup-code or /api/v1/license without valid session cookie
- Admin UI access from external IPs not in the approved jump-host range
- Web shell artifacts: new .cgi or .pl files written to /home/webserver/htdocs/ outside patch windows
- Outbound connections from the ICS appliance to non-Ivanti IPs on port 443 or 4444 (beacon indicator)
- debug.log entries containing plaintext credential strings (password=, pwd=) from failed SAML assertions
- Single VPN session authenticating as multiple different users within a 10-minute window (session token replay)

### SPL
```spl
index=ivanti sourcetype=ivanti:connectsecure
| search (uri_path="*/api/v1/totp/*" OR uri_path="*/api/v1/license*") status!=401
| where NOT match(src_ip, "^10\.0\.9\.")
| stats count by src_ip, uri_path, status, user
| where count >= 1
| sort - count
```

### Exclusions
- Ivanti TAC support tunnel sessions from 198.18.0.0/15 (vendor support range)
- Scheduled license check from svc-ivanti-mon (10.0.9.55) — API call every 6h is expected
- Patch-window appliance restarts — correlate with change management ticket

### Attack Paths
- T1078.002 | Valid Accounts: Domain Accounts | critical | Auth bypass grants unauthenticated access to VPN — attacker harvests cached AD credentials from active sessions and uses them for lateral movement into the corporate network
- T1505.003 | Web Shell | high | CVE-2024-21887 command injection used to stage a persistent web shell on the ICS appliance — provides durable foothold that survives credential rotation
- T1041 | Exfiltration Over C2 Channel | high | Compromised VPN appliance acts as C2 relay — outbound connections to attacker infrastructure are indistinguishable from legitimate VPN gateway traffic without appliance-level log inspection

---

## SK-058 — EDR and Log Source Tamper Detection

> type: domain | category: defense-evasion | category-label: Defense Evasion | ttps: T1562.001, T1070.001
> author: akowalski | version: v1.0 | updated: 2026-05-12 | agents: tradecraft, detection, validation

Monitors for tampering with EDR sensors (CrowdStrike Falcon), Sysmon, and Windows Event Log service. Any attempt to stop, uninstall, or disable these platforms is a strong indicator of pre-ransomware or exfiltration staging. Splunk ES will lose visibility within minutes of a successful tamper.

### Patterns
- EventCode 7045 or 7036: CrowdStrike (CSFalconService), Sysmon (SysmonDrv), or Windows Event Log service state change to Stopped or Disabled
- EventCode 4699 (audit policy change) removing Security log auditing categories
- wevtutil.exe with cl (clear-log) argument against Security, System, or Sysmon log channels
- Registry key deletion under HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv

### SPL
```spl
index=wineventlog (EventCode=7036 OR EventCode=7045)
| where match(ServiceName, "(?i)(CSFalcon|Sysmon|EventLog|WinDefend)")
| where match(Message, "(?i)(stopped|disabled|deleted)")
| table _time, host, ServiceName, Message
| append [search index=sysmon EventCode=1 Image="*wevtutil*" CommandLine="*cl *"
  | table _time, host, User, CommandLine]
```

### Exclusions
- Planned CrowdStrike sensor updates — correlate with change management ticket, must originate from JUMP-01
- Sysmon version upgrades from IT Ops — brief stop/start expected during update window
- No legitimate reason for wevtutil cl on Security or Sysmon logs in production

### Attack Paths
- T1562.002 | Disable Windows Event Logging | critical | Without Sysmon and Windows event logs, the attack chain becomes invisible to Splunk ES — attacker has free rein to perform lateral movement and exfil undetected
- T1070.004 | File Deletion | high | Log clearing typically paired with file deletion of staging directories to remove forensic artifacts before IR engagement
- T1486 | Data Encrypted for Impact | high | EDR tamper is a direct ransomware precursor — disabling CrowdStrike removes the primary runtime prevention control before encryption begins

---
