# Tradecraft Skills Repository

Analyst-authored hunting skills. Each skill is a reusable detection pattern with SPL, exclusions, and downstream attack-path context. Edit this file to add or update skills — changes are reflected in the Knowledge Base on next page load.

`skillType` values:
- `tactic` — Generic MITRE ATT&CK technique knowledge, applies cross-org
- `domain` — Environment/org-specific: tuned to THIS network's topology, tooling, naming conventions, and known-good baselines

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

## SK-038 — Kerberoasting — Service Account FP Filter

> type: domain | category: credential-access | category-label: Credential Access | ttps: T1558.003
> author: jsmith | version: v2.1 | updated: 2026-04-29 | agents: hypothesis, tradecraft, detection

Reduces false positives in Kerberoasting detection by excluding known-good SPN requesters — MSSQL, BackupExec, and scheduled task service accounts. Pre-loads CMDB-sourced SPN exclusion list and tunes the RC4 TGS threshold to org-specific baseline noise.

### Patterns
- TGS-REQ for RC4 (0x17) tickets from interactive user sessions — not service accounts
- Bulk SPN enumeration: >5 unique SPNs requested within 60s from the same source IP
- TGS requests targeting accounts where pwdLastSet > 180 days (stale passwords)
- Kerberos pre-auth disabled flag set on account — high-value targeting indicator

### SPL
```spl
index=wineventlog EventCode=4769 TicketEncryptionType=0x17
| where NOT match(ServiceName, "^krbtgt|^MSSQLSvc|^BackupExec|^WSMAN")
| stats count by AccountName, ServiceName, IpAddress
| where count > 3
```

### Exclusions
- BackupExec/BEService — high-volume SPN lookups expected during backup jobs
- MSSQLSvc/* — SQL service account auth is noisy by design
- WSMAN/* — WinRM service accounts in managed server OU

### Attack Paths
- T1078.002 | Valid Accounts: Domain Accounts | high | Cracked service account passwords enable direct authentication to servers the account legitimately accesses
- T1021.002 | Remote Services: SMB/Admin Shares | high | Service account credentials used for lateral movement to domain-joined hosts via SMB — particularly servers with SPN registrations
- T1558.001 | Golden Ticket | medium | If krbtgt hash obtained via DCSync (reachable once domain admin creds are cracked), forged TGTs grant unrestricted domain access

---

## SK-031 — Firewall Anomaly — East-West Lateral Spread

> type: domain | category: lateral-movement | category-label: Lateral Movement | ttps: T1021.001, T1021.002, T1570
> author: akowalski | version: v1.0 | updated: 2026-03-11 | agents: tradecraft, dataeng

Identifies abnormal east-west firewall flows indicative of lateral movement — new RDP/SMB paths between previously unconnected segments, or port scans from workstation-class assets. Built on a 30-day flow baseline; flags net-new paths not seen in prior observation window.

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
- T1003.001 | LSASS Memory | high | Credential access on newly reached host to harvest hashes for the next lateral hop — standard post-movement step
- T1570 | Lateral Tool Transfer | high | Attacker tooling deployed to compromised workstations via SMB admin shares once lateral path is established
- T1049 | System Network Connections Discovery | medium | Network enumeration from beachhead host to map additional targets and identify high-value systems to pivot toward

---

## SK-029 — LSASS Credential Dumping — EDR Evasion Variants

> type: tactic | category: credential-access | category-label: Credential Access | ttps: T1003.001
> author: rmendez | version: v3.0 | updated: 2026-05-01 | agents: tradecraft, detection, validation

Covers modern LSASS dump evasion techniques that bypass standard process-access rules — handle duplication via NtDuplicateObject, direct syscall stubs, and PPL bypass using BYOVD. Derived from red team debrief notes and CrowdStrike incident data across three engagements.

### Patterns
- NtReadVirtualMemory calls to lsass.exe from non-AV/EDR processes (Sysmon EC10)
- Shadow copy creation (vssadmin) immediately followed by an LSASS-sized file read
- Handle duplication to lsass via NtDuplicateObject from an unsigned DLL
- comsvcs.dll MiniDump invoked via wmic.exe or cmd.exe — fileless variant

### SPL
```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where NOT match(SourceImage, "(?i)(defender|MsMpEng|crowdstrike|CSFalcon|carbon)")
| table _time, SourceImage, GrantedAccess, CallTrace
```

### Exclusions
- CrowdStrike sensor (CSFalconService.exe) — legitimate LSASS inspection by EDR
- Windows Defender (MsMpEng.exe) — AV scanning access is expected

### Attack Paths
- T1550.002 | Pass-the-Hash | high | NTLM hashes extracted from LSASS enable lateral movement to other Windows hosts without cracking the password
- T1078.002 | Valid Accounts: Domain Accounts | high | Clear-text credentials (if present in LSASS memory) enable direct domain authentication and privilege escalation
- T1003.006 | DCSync | medium | Domain admin credentials obtained via LSASS give access to DCSync — extracts all domain hashes from AD replication

---

## SK-022 — DNS Beaconing Pattern Recognition

> type: tactic | category: c2 | category-label: Command & Control | ttps: T1071.004, T1568.002
> author: jsmith | version: v1.3 | updated: 2026-02-18 | agents: hypothesis, tradecraft

Statistical approach to identifying C2 DNS beaconing using periodicity scoring, Shannon entropy on query names, and domain age gating. Tuned against org-specific resolver noise — reduces FP rate to <3% on known-good traffic. Catches JA3-agnostic C2 that evades TLS inspection.

### Patterns
- Query interval coefficient of variation < 0.1 over 20+ requests (high periodicity)
- NXDOMAIN rate > 40% from a single source within a 10-minute window
- Shannon entropy of queried domain labels > 3.5 (DGA indicator)
- Domain registered < 30 days with MX record present but no prior org traffic

### SPL
```spl
index=dns
| stats count, stdev(interval) as sd, avg(interval) as avg_i by src_ip, query
| eval cv=sd/avg_i
| where cv < 0.1 AND count > 20
| sort - count
```

### Exclusions
- Windows Update / Microsoft CDN domains (*.windowsupdate.com, *.microsoft.com)
- Known telemetry endpoints listed in org threat-intel exclusion feed

### Attack Paths
- T1041 | Exfiltration Over C2 Channel | high | Established DNS tunnel used for data exfiltration — low-bandwidth but highly covert; files chunked into query labels
- T1105 | Ingress Tool Transfer | high | Additional implant stages or tooling downloaded via DNS channel using TXT or A record responses as transport
- T1071.001 | Application Layer Protocol: Web | medium | Pivot from DNS C2 to HTTP/S for higher-bandwidth operations once initial foothold is confirmed stable

---

## SK-017 — PowerShell Obfuscation Fingerprinting

> type: tactic | category: execution | category-label: Execution | ttps: T1059.001, T1027
> author: akowalski | version: v2.2 | updated: 2026-01-30 | agents: tradecraft, detection

Identifies PowerShell obfuscation patterns including encoding stacking, backtick insertion, character substitution, and environment variable concatenation. Covers both classic Invoke-Obfuscation output and manual obfuscation seen in living-off-the-land intrusions.

### Patterns
- CommandLine length > 500 chars with >30% special characters
- Base64 payload nested inside -EncodedCommand (double-encoded)
- Backtick insertion splitting execution keywords: i`e`x, `n`e`t, In`voke
- String concatenation constructing Invoke-Expression or iex via Join/Format

### SPL
```spl
index=sysmon EventCode=1 (Image="*powershell*" OR Image="*pwsh*")
| eval cmd_len=len(CommandLine)
| where cmd_len > 500 OR match(CommandLine, "(?i)i`|iex|EncodedCommand.+EncodedCommand")
| table _time, host, user, CommandLine
```

### Exclusions
- SCCM/ConfigMgr scripts — must be code-signed and originate from 10.0.5.20
- Legitimate admin scripts under C:\Windows\CCM\ or C:\Program Files\...

### Attack Paths
- T1055 | Process Injection | high | Obfuscated PS commonly delivers shellcode injected into legitimate Windows processes — explorer.exe, svchost.exe
- T1105 | Ingress Tool Transfer | medium | Obfuscated PS stages download additional payloads from C2 — second-stage implants, credential dumpers, lateral movement tools
- T1003.001 | LSASS Memory | medium | Credential dumping typically follows once execution capability is established — obfuscated PS is often the delivery mechanism
