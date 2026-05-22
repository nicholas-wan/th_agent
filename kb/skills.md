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

---

## SK-046 — DCSync Attack Detection

> type: tactic | category: credential-access | category-label: Credential Access | ttps: T1003.006
> author: rmendez | version: v1.4 | updated: 2026-05-10 | agents: hypothesis, tradecraft, detection

Detects DCSync attacks by identifying non-DC accounts invoking Directory Replication Service (DS-Replication-Get-Changes-All). Mimikatz `lsadump::dcsync` and Impacket `secretsdump.py` both trigger EventCode 4662. High-confidence — only DCs and Azure AD Connect legitimately perform full replication.

### Patterns
- EventCode 4662 with Properties containing `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes-All) from a non-DC subject
- Replication request from a workstation-class asset or non-CORP\SYSTEM account
- Spike in 4662 events from a single account within a 60-second window (bulk sync indicator)
- Account performing DCSync not in Domain Controllers or Azure AD Connect OU

### SPL
```spl
index=wineventlog EventCode=4662
| search Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
| where NOT match(SubjectUserName, "(?i)^WIN-DC|MSOL_|ADSync|\$$")
| stats count by SubjectUserName, SubjectDomainName, host, _time
| where count >= 1
| sort - _time
```

### Exclusions
- Domain Controllers (host ends in WIN-DC*) — legitimate AD replication
- Azure AD Connect account (MSOL_* / ADSync) — delta sync every 30 min
- CORP\SYSTEM — OS-level replication context

### Attack Paths
- T1558.001 | Golden Ticket | critical | krbtgt NTLM hash extracted via DCSync enables forged Kerberos TGTs with arbitrary lifetimes and group memberships
- T1078.002 | Valid Accounts: Domain Accounts | high | All domain account hashes extracted — attacker can authenticate as any user without cracking passwords (Pass-the-Hash)
- T1003.001 | LSASS Memory | medium | DCSync often follows initial LSASS dump — attacker escalates from workstation credentials to domain-wide hash extraction

---

## SK-047 — Scheduled Task Persistence

> type: tactic | category: persistence | category-label: Persistence | ttps: T1053.005
> author: akowalski | version: v2.0 | updated: 2026-04-22 | agents: tradecraft, detection

Identifies suspicious scheduled task creation via EventCode 4698, filtering out known-good management tooling. High-value targets: tasks created by interactive users outside business hours, tasks running from temp or user-writable directories, and tasks invoking scripting engines.

### Patterns
- EventCode 4698 (scheduled task created) where TaskContent contains `cmd.exe`, `powershell`, `wscript`, or `cscript`
- Task action path resolving to %TEMP%, %APPDATA%, C:\Users\, or C:\ProgramData\ (user-writable)
- Task created by an account that is not a known admin or automated provisioning account
- EventCode 4702 (task updated) after initial creation within the same session — covers modification to evade baseline

### SPL
```spl
index=wineventlog EventCode=4698
| rex field=TaskContent "<Command>(?P<cmd>[^<]+)</Command>"
| where match(cmd, "(?i)(powershell|cmd\.exe|wscript|cscript|mshta|rundll32)")
| where NOT match(SubjectUserName, "(?i)(SYSTEM|svc-sccm|svc-backup|adm-itops)")
| table _time, host, SubjectUserName, TaskName, cmd
```

### Exclusions
- SCCM/ConfigMgr task sequences (SubjectUserName = svc-sccm, task name begins SCCM_)
- IT Operations automation tasks created from JUMP-01 during change windows
- Windows built-in tasks under \Microsoft\Windows\ path

### Attack Paths
- T1059.001 | PowerShell | high | Scheduled task executes encoded PS payload at next logon or system event — common persistence mechanism for post-exploitation frameworks
- T1078.002 | Valid Accounts | medium | Task created under a compromised service account runs with that account's privileges at scheduled intervals
- T1105 | Ingress Tool Transfer | medium | Task triggers outbound connection to C2 to download next-stage tooling when security tools are not actively monitoring

---

## SK-048 — CORP Privileged Account Off-Hours Activity

> type: domain | category: credential-access | category-label: Credential Access | ttps: T1078.002, T1078.003
> author: jsmith | version: v1.5 | updated: 2026-05-08 | agents: hypothesis, tradecraft

CORP.LOCAL-specific: monitors adm-itops, Domain Admins, and Enterprise Admins for logon activity outside approved maintenance windows (Mon–Fri 07:00–19:00 UTC). Baseline-checked against JUMP-01 source. Any privileged logon from a non-JUMP-01 source is high-confidence.

### Patterns
- EventCode 4624 (LogonType 2 or 10) for accounts in Domain Admins / Enterprise Admins outside maintenance window
- Logon source IP not matching JUMP-01 (10.0.9.10) — privileged access must go through PAM
- Interactive logon to any DC (WIN-DC01, WIN-DC02) from a non-JUMP-01 workstation
- adm-itops account session not recorded in CyberArk PSM session log (correlation check)

### SPL
```spl
index=wineventlog EventCode=4624 LogonType IN (2, 10)
| where match(TargetUserName, "(?i)^adm-|Administrator$")
| eval hour=tonumber(strftime(_time, "%H")), dow=strftime(_time, "%u")
| where (hour < 7 OR hour > 19) OR dow IN ("6","7")
| where NOT (IpAddress="10.0.9.10" OR IpAddress="::1" OR IpAddress="-")
| table _time, TargetUserName, IpAddress, Workstation, host
```

### Exclusions
- Logons from JUMP-01 (10.0.9.10) — all privileged access is expected to originate here
- Approved emergency change window logons — cross-reference CyberArk session ticket
- CORP\SYSTEM and machine accounts (ending in $)

### Attack Paths
- T1003.006 | DCSync | critical | Domain Admin credentials used from non-PAM workstation suggest credential theft — DCSync is likely next step to extract domain hashes
- T1078.002 | Valid Accounts: Domain Accounts | high | Off-hours admin logon from unexpected source is strong indicator of lateral movement with stolen privileged credentials
- T1484.001 | Group Policy Modification | medium | Domain Admin access enables GPO modification for mass malware deployment or persistence across all domain-joined systems

---

## SK-049 — WMI Lateral Movement and Persistence

> type: tactic | category: lateral-movement | category-label: Lateral Movement | ttps: T1047, T1546.003
> author: rmendez | version: v1.1 | updated: 2026-03-28 | agents: tradecraft, detection

Covers WMI remote execution (wmic /node:, Invoke-WmiMethod) and WMI event subscription persistence (ActiveScriptEventConsumer, CommandLineEventConsumer). WMI-based lateral movement is widely used because it generates limited process telemetry compared to PsExec and is often whitelisted by AV.

### Patterns
- WmiPrvSE.exe spawning cmd.exe, powershell.exe, or any scripting engine (Sysmon EC1 parent=WmiPrvSE)
- WMI permanent event subscription creation (EventCode 5857–5861) by a non-admin account
- Remote WMI via port 135 (DCOM) from a workstation-class asset to a server or DC
- wmic.exe with `/node:` argument from an account that does not normally use remote WMI

### SPL
```spl
index=sysmon EventCode=1 ParentImage="*WmiPrvSE.exe"
| where match(Image, "(?i)(cmd\.exe|powershell|wscript|mshta|certutil|bitsadmin)")
| table _time, host, User, Image, CommandLine, ParentCommandLine
```

### Exclusions
- SCCM WMI inventory queries (ParentCommandLine contains CCM_Invoke or WmiInventory)
- Splunk WMI input (WmiPrvSE spawning splunkd children for WMI data collection)
- Antivirus WMI scanning — whitelist by hash of known-good AV WMI consumers

### Attack Paths
- T1021.002 | Remote Services: SMB/Admin Shares | high | WMI execution establishes remote presence; SMB admin shares then used to transfer tools to the newly reached host
- T1003.001 | LSASS Memory | high | WmiPrvSE→cmd→PS credential dump chain is a classic technique — the WMI hop obfuscates the originating process in many EDRs
- T1070.001 | Indicator Removal: Clear Windows Event Logs | medium | WMI persistence consumers commonly execute log-clearing scripts to remove evidence of the initial exploitation chain

---

## SK-050 — LOLBin Proxy Execution

> type: tactic | category: defense-evasion | category-label: Defense Evasion | ttps: T1218, T1216
> author: akowalski | version: v2.3 | updated: 2026-05-03 | agents: tradecraft, detection, validation

Living-off-the-Land Binary abuse: execution via signed Windows binaries to evade application whitelisting. Covers the most common LOLBins observed in intrusions: mshta, regsvr32, rundll32 (comsvcs), certutil, msiexec, and wmic. Each has a distinct command-line signature tracked by this skill.

### Patterns
- mshta.exe executing a remote URL (`mshta http`) or encoded vbscript
- regsvr32.exe with `/s /u /i:http` (Squiblydoo) or executing a DLL from %TEMP%
- certutil.exe with `-decode`, `-urlcache`, or `-verifyctl` arguments against non-MS URLs
- msiexec.exe with `/q /i http://` — silent MSI install from remote source

### SPL
```spl
index=sysmon EventCode=1
| where (match(Image,"(?i)mshta\.exe") AND match(CommandLine,"(?i)http|vbscript|javascript"))
  OR (match(Image,"(?i)regsvr32\.exe") AND match(CommandLine,"(?i)/i:http|scrobj"))
  OR (match(Image,"(?i)certutil\.exe") AND match(CommandLine,"(?i)urlcache|decode|-f http"))
  OR (match(Image,"(?i)msiexec\.exe") AND match(CommandLine,"(?i)/q.*/i http"))
| table _time, host, User, Image, CommandLine
```

### Exclusions
- certutil certificate management by PKI team from JUMP-01 — validate source host
- msiexec silent installs from SCCM (parent process = ccmexec.exe or CcmSetup.exe)
- regsvr32 registrations from C:\Windows\System32\ or C:\Program Files\ with signed DLLs

### Attack Paths
- T1059.001 | PowerShell | high | LOLBin execution typically downloads and invokes an encoded PS script as the second stage — the LOLBin acts as a loader to evade initial detection
- T1055.001 | DLL Injection | medium | Rundll32 and regsvr32 used to load malicious DLLs into memory — shellcode injection into trusted processes follows
- T1071.001 | Application Layer: Web | medium | LOLBin makes outbound HTTP/S to C2 via trusted signed binary — URL filtering may not inspect traffic from certutil or msiexec

---

## SK-051 — LDAP Enumeration from Workstations

> type: tactic | category: discovery | category-label: Discovery | ttps: T1087.002, T1069.002
> author: jsmith | version: v1.0 | updated: 2026-04-14 | agents: hypothesis, tradecraft

Detects bulk LDAP queries from non-standard sources — workstations executing AD enumeration tools such as BloodHound, ADFind, or PowerView. Key indicator: high-volume LDAP queries (EventCode 1644 / network LDAP) from workstation-class assets during interactive user sessions.

### Patterns
- EventCode 1644 (LDAP search statistics) showing >200 results returned to a workstation source
- Network LDAP (TCP 389) connections from Corp-Workstations VLAN to DC VLAN outside SCCM/auth baseline
- SharpHound collection artifacts: ldap query for `(objectClass=*)` with large pageSize
- ADFind.exe or ldifde.exe execution from non-admin workstation (rare in normal ops)

### SPL
```spl
index=wineventlog EventCode=4662 OR EventCode=4661
| stats count by SubjectUserName, host
| where count > 100
| join host [search index=sysmon EventCode=1
  (CommandLine="*bloodhound*" OR CommandLine="*adfind*" OR CommandLine="*ldifde*"
  OR CommandLine="*powerview*")]
| table _time, host, SubjectUserName, count
```

### Exclusions
- SCCM hardware/software inventory scans from svc-sccm — scheduled and high-volume by design
- Splunk LDAP input (svc-splunk querying for user/group data for identity correlation)
- adm-itops LDAP activity from JUMP-01 — privileged AD management is expected

### Attack Paths
- T1078.002 | Valid Accounts | high | BloodHound graph reveals shortest path to Domain Admin — attacker immediately targets identified accounts for credential theft
- T1484.001 | Group Policy Modification | medium | AD enumeration reveals GPO structure and identifies GPOs with weak ACLs that can be hijacked for mass deployment
- T1558.003 | Kerberoasting | medium | LDAP enumeration identifies service accounts with SPNs — Kerberoastable targets extracted and handed to offline cracker

---

## SK-052 — Shadow Copy Deletion

> type: tactic | category: impact | category-label: Impact | ttps: T1490
> author: akowalski | version: v1.2 | updated: 2026-02-09 | agents: tradecraft, detection

High-confidence ransomware pre-staging indicator. Shadow copy deletion via vssadmin, wmic, or PowerShell is performed immediately before encryption in virtually all ransomware families (LockBit, BlackCat, BlackMatter, Conti). Near-zero false-positive rate in corporate environments.

### Patterns
- `vssadmin delete shadows /all /quiet` or equivalent (EventCode 4688 / Sysmon EC1)
- `wmic shadowcopy delete` from any non-backup context
- PowerShell `Get-WmiObject Win32_ShadowCopy | Remove-WmiObject`
- bcdedit.exe modifying recovery options (`/set {default} recoveryenabled No`)

### SPL
```spl
index=sysmon EventCode=1
| where (match(Image,"(?i)vssadmin") AND match(CommandLine,"(?i)delete"))
  OR (match(Image,"(?i)wmic") AND match(CommandLine,"(?i)shadowcopy.+delete"))
  OR (match(Image,"(?i)bcdedit") AND match(CommandLine,"(?i)recoveryenabled.+No"))
| table _time, host, User, Image, CommandLine, ParentImage
```

### Exclusions
- svc-backup deleting shadows post-backup on Server Farm hosts — correlate with scheduled backup window
- No other exclusions expected — this command in production is almost always malicious

### Attack Paths
- T1486 | Data Encrypted for Impact | critical | Shadow deletion is immediate ransomware precursor — if seen, assume encryption imminent; isolate host and invoke IR
- T1070.004 | File Deletion | high | Attacker removes recovery options to maximise impact and prevent restoration without paying ransom
- T1082 | System Information Discovery | medium | bcdedit modification often paired with system enumeration to identify additional recovery paths (RAID, network backups) to neutralise

---

## SK-053 — Cobalt Strike Named Pipe C2 Patterns

> type: tactic | category: c2 | category-label: Command & Control | ttps: T1071.001, T1572
> author: rmendez | version: v2.1 | updated: 2026-05-15 | agents: tradecraft, detection, validation

Identifies Cobalt Strike beacon SMB channel via named pipe artefacts. Default and common custom pipe names are detectable via Sysmon EventCode 17/18 (Pipe Created/Connected). Covers both default profiles and malleable C2 profiles commonly used by red teams and threat actors.

### Patterns
- Named pipe creation matching Cobalt Strike defaults: `\postex_*`, `\msagent_*`, `\mojo.*`, `\interprocess_*`, `\samr`, `\status_*`
- Pipe created by a process that is not a known IPC user (Word, Excel, Outlook creating pipes is anomalous)
- Sysmon EC17 pipe names with high-entropy random suffixes (>8 random chars) from non-system processes
- SMB pipe connect (EC18) from a remote host to a local pipe not associated with normal IPC (no corresponding EC3 network event from legitimate service)

### SPL
```spl
index=sysmon EventCode=17
| where match(PipeName, "(?i)(\\postex_|\\msagent_|\\mojo\.|\\interprocess_|\\status_|\\samr$)")
  OR (match(PipeName, "[a-f0-9]{8,}") AND NOT match(Image, "(?i)(chrome|firefox|teams|slack)"))
| table _time, host, Image, PipeName, User
```

### Exclusions
- Chrome/Chromium IPC pipes (mojo.* from chrome.exe is normal)
- Slack, Teams, and other Electron apps that use mojo IPC extensively
- Named pipes from C:\Windows\System32\ signed Microsoft binaries

### Attack Paths
- T1021.002 | Remote Services: SMB/Admin Shares | high | CS SMB beacon chains hop through hosts using named pipe transport — lateral movement across air-gapped or firewalled segments
- T1055 | Process Injection | high | Beacon injects into legitimate processes (svchost, explorer) and creates pipes from those process contexts to blend with normal IPC traffic
- T1041 | Exfiltration Over C2 Channel | medium | Staged data exfiltration via SMB C2 pipe evades DLP tools tuned only for HTTP/S — particularly effective across VLAN boundaries

---

## SK-054 — CORP Service Account Lateral Movement Baseline

> type: domain | category: lateral-movement | category-label: Lateral Movement | ttps: T1078, T1021.002
> author: jsmith | version: v1.3 | updated: 2026-05-02 | agents: hypothesis, tradecraft

CORP.LOCAL-specific: each service account has a defined host scope. Any authentication from a service account to a host outside its approved scope is a high-confidence indicator of credential abuse. Baseline scopes: svc-backup→Server Farm+DC VLAN, svc-sql→SQL-DB01 only, svc-splunk→SPLUNK-ES only.

### Patterns
- EventCode 4624 (network logon) by svc-* accounts to hosts outside their defined scope
- svc-backup authenticating to workstation-class assets (10.0.3.0/24) — never legitimate
- svc-sql authenticating anywhere other than SQL-DB01 (10.0.2.30)
- Any service account logon with LogonType 2 (interactive) — service accounts must never log on interactively

### SPL
```spl
index=wineventlog EventCode=4624
| where match(TargetUserName, "^svc-")
| lookup asset_scope_lookup AccountName AS TargetUserName OUTPUT AllowedScope
| where NOT cidrmatch(AllowedScope, IpAddress)
| table _time, TargetUserName, IpAddress, LogonType, host
```

### Exclusions
- svc-backup to DR Site (10.10.0.0/16) during nightly replication window 01:00–05:00 UTC
- svc-splunk to any host on UDP 514 / TCP 9997 (log collection — read-only, expected)
- Logon events from 127.0.0.1 or :: (loopback — not lateral movement)

### Attack Paths
- T1003.001 | LSASS Memory | high | Service account with broad host access enables credential harvest from multiple systems — particularly dangerous for svc-backup (Backup Operators group)
- T1570 | Lateral Tool Transfer | high | svc-backup SMB access to Server Farm enables file staging and tool deployment without additional lateral movement steps
- T1078.003 | Valid Accounts: Local Accounts | medium | Service accounts frequently reuse passwords across hosts — compromise of one enables pass-the-hash to all machines with matching credential

---

## SK-055 — Registry Persistence — Run Keys and Startup Folders

> type: tactic | category: persistence | category-label: Persistence | ttps: T1547.001
> author: akowalski | version: v1.1 | updated: 2026-01-20 | agents: tradecraft, detection

Run key and startup folder modifications are used by commodity malware and APT alike. Focuses on writes to HKCU/HKLM Run keys from non-admin contexts, and startup folder drops not attributable to known software installers. Sysmon EC13 (registry set) provides reliable telemetry.

### Patterns
- Sysmon EC13: TargetObject matches `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*` or `HKCU\...\Run*` with Image not a signed installer
- Registry write to `\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` (Userinit or Shell substitution)
- File drop to `C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`
- EC13 from a process in %TEMP% or %APPDATA% modifying Run keys

### SPL
```spl
index=sysmon EventCode=13
| where match(TargetObject, "(?i)(\\CurrentVersion\\Run|\\Winlogon\\Userinit|\\Winlogon\\Shell)")
| where NOT match(Image, "(?i)(msiexec|setup|installer|ccmsetup|Teams|OneDrive|Chrome)")
| table _time, host, User, Image, TargetObject, Details
```

### Exclusions
- Legitimate software installers (msiexec, setup.exe with valid signature from known vendor)
- OneDrive, Teams, Slack — known Run key users during user-context installation
- SCCM software deployment (ccmexec.exe) writing application Run keys

### Attack Paths
- T1059.001 | PowerShell | high | Run key executes encoded PS loader on next user logon — provides durable persistence that survives reboots without requiring elevated privileges
- T1078.002 | Valid Accounts | medium | If persistence is under a service account Run key context, it executes with that account's domain privileges on each system start
- T1036.005 | Masquerading: Match Legitimate Name | medium | Malicious entries often impersonate legitimate software names (e.g., `MicrosoftEdgeUpdater`) — check Details field for unexpected paths

---

## SK-056 — Pass-the-Hash Detection via Anomalous NTLMv2 Auth

> type: tactic | category: lateral-movement | category-label: Lateral Movement | ttps: T1550.002
> author: rmendez | version: v2.0 | updated: 2026-04-18 | agents: tradecraft, detection

Identifies Pass-the-Hash by correlating NTLMv2 network logons (EventCode 4624, LogonType 3, AuthPackage=NTLM) from hosts where the user has no interactive session. PtH is distinguishable from Kerberos-based lateral movement by the NTLM authentication package and lack of matching EventCode 4648 on source.

### Patterns
- EventCode 4624 LogonType=3, AuthenticationPackageName=NTLM from a workstation-class source
- No corresponding EventCode 4648 (explicit credential use) on source host — indicates hash replay rather than credential entry
- NTLM auth to DC VLAN (10.0.1.0/24) from non-server asset — DCs prefer Kerberos; NTLM here is anomalous
- Same user NTLM-authenticating to >3 unique destinations within 10 minutes

### SPL
```spl
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
| where NOT match(TargetUserName, "(?i)ANONYMOUS|SYSTEM|\$$")
| where NOT match(IpAddress, "^10\.0\.(5|9)\.")
| stats dc(host) as destinations, values(host) as dest_hosts by TargetUserName, IpAddress
| where destinations > 2
| table TargetUserName, IpAddress, destinations, dest_hosts
```

### Exclusions
- Legacy applications that require NTLM (validate against known-app list in CMDB)
- Printer authentication — typically NTLM from client to print server (scope to non-printer destinations)
- IIS Anonymous Auth using NTLM — web apps in DMZ VLAN may require this

### Attack Paths
- T1021.002 | Remote Services: SMB/Admin Shares | high | PtH enables admin share access without knowing plaintext password — attacker can browse and write to C$, ADMIN$ across reached hosts
- T1003.001 | LSASS Memory | high | Hash obtained from earlier LSASS dump is replayed — PtH is often the second step after credential dumping, completing the lateral chain
- T1078.002 | Valid Accounts | medium | Successful PtH establishes authenticated sessions indistinguishable from legitimate user activity — low noise during normal business hours

---

## SK-057 — Office Macro Execution Chain

> type: tactic | category: execution | category-label: Execution | ttps: T1204.002, T1566.001
> author: jsmith | version: v1.4 | updated: 2026-03-05 | agents: hypothesis, tradecraft, detection

Identifies macro execution chains originating from Office products (Word, Excel, PowerPoint). Key indicator: child process spawned by an Office app that is not a known helper. Covers both traditional VBA macros and newer XLM/4.0 macros, as well as DDE and SYLK-based execution.

### Patterns
- Sysmon EC1: cmd.exe, powershell.exe, wscript.exe, or mshta.exe with parent = WINWORD, EXCEL, POWERPNT, OUTLOOK
- Office app writing an executable or script file to %TEMP%, %APPDATA%, or C:\Users\Public\
- EXCEL spawning regsvr32.exe or rundll32.exe (XLM 4.0 macro pattern)
- Office process making outbound network connection to non-Microsoft IP within 5 seconds of document open (EC3)

### SPL
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)(WINWORD|EXCEL|POWERPNT|OUTLOOK)\.exe")
| where match(Image, "(?i)(cmd\.exe|powershell|wscript|mshta|regsvr32|rundll32|certutil)")
| table _time, host, User, ParentImage, Image, CommandLine
```

### Exclusions
- Office update processes (OfficeClickToRun.exe, setup.exe from Office install path)
- Outlook spawning Lync/Teams helper for calendar integration
- Excel spawning Python.exe via xlwings/openpyxl — validate against approved data-science tooling list

### Attack Paths
- T1059.001 | PowerShell | high | Office macro drops encoded PS stager — classic first-stage payload that downloads beacon implant from C2 infrastructure
- T1547.001 | Registry Run Keys | medium | Macro execution establishes persistence immediately after initial execution to survive document close and system reboot
- T1071.004 | DNS | medium | Macro-delivered implant uses DNS C2 as initial comms channel — lower detection rate than HTTP on strict egress environments

---

## SK-058 — CORP EDR and Log Source Tamper Detection

> type: domain | category: defense-evasion | category-label: Defense Evasion | ttps: T1562.001, T1070.001
> author: akowalski | version: v1.0 | updated: 2026-05-12 | agents: tradecraft, detection, validation

CORP.LOCAL-specific: monitors for tampering with CrowdStrike Falcon, Sysmon, and Windows Event Log service on CORP endpoints. Any attempt to stop, uninstall, or disable these services is a strong indicator of pre-ransomware or exfiltration staging. Splunk ES will lose visibility within minutes of a successful tamper.

### Patterns
- EventCode 7045 or 7036: CrowdStrike (CSFalconService), Sysmon (SysmonDrv), or Windows Event Log service state change to Stopped or Disabled
- EventCode 4699 (audit policy change) removing Security log auditing categories
- wevtutil.exe with `cl` (clear-log) argument against Security, System, or Sysmon log channels
- Registry key deletion under `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv`

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
- Planned CrowdStrike sensor updates — correlate with change management ticket and originate from 10.0.9.10 (JUMP-01)
- Sysmon version upgrades from IT Ops — brief stop/start expected during update
- No legitimate reason for wevtutil cl on Security or Sysmon logs in production

### Attack Paths
- T1562.002 | Disable Windows Event Logging | critical | Without Sysmon and Windows event logs, the attack chain becomes invisible to Splunk ES — attacker has free rein to perform lateral movement and exfil undetected
- T1070.004 | File Deletion | high | Log clearing typically paired with file deletion of staging directories to remove forensic artefacts before IR engagement
- T1486 | Data Encrypted for Impact | high | EDR tamper is a direct ransomware precursor — disabling CrowdStrike removes the primary runtime prevention control before encryption begins

---

## SK-059 — DCOM Lateral Movement

> type: tactic | category: lateral-movement | category-label: Lateral Movement | ttps: T1021.003
> author: rmendez | version: v1.0 | updated: 2026-04-07 | agents: tradecraft, detection

Detects DCOM-based lateral movement using MMC20.Application, ShellWindows, ShellBrowserWindow, and Excel.Application objects — all commonly abused for remote code execution without dropping files. DCOM abuse generates minimal process telemetry but leaves clear network signatures on port 135 followed by dynamic RPC ports.

### Patterns
- mmc.exe spawning cmd.exe or PowerShell with a parent chain tracing to svchost.exe (DCOM host)
- Sysmon EC1: unexpected parent process svchost.exe with DcomLaunch service context spawning scripting engines
- Network connections from workstation-class assets to port 135 on Server Farm or DC VLAN assets followed by ephemeral RPC ports (49152–65535)
- EventCode 4624 LogonType=3 immediately followed by EC1 from svchost.exe on destination host

### SPL
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)svchost\.exe")
| where match(Image, "(?i)(cmd\.exe|powershell|mshta|cscript|wscript)")
| where match(ParentCommandLine, "(?i)(DcomLaunch|imgsvc|-k netsvcs)")
| table _time, host, User, Image, CommandLine, ParentCommandLine
```

### Exclusions
- Windows Management Instrumentation (WmiPrvSE is a child of svchost — covered by SK-049)
- Print Spooler spawning splwow64.exe — expected DCOM print rendering
- COM surrogate (dllhost.exe) spawned by svchost for shell extension hosting

### Attack Paths
- T1003.001 | LSASS Memory | high | DCOM execution on a newly reached host is immediately followed by credential harvesting to extend lateral movement — no additional tooling required to spawn credential dumper
- T1021.002 | Remote Services: SMB/Admin Shares | high | DCOM establishes execution context; SMB is then used to transfer tooling and exfil data from the newly reached host
- T1078.002 | Valid Accounts | medium | DCOM requires authenticated session — PtH or valid domain credentials obtained earlier are consumed to initiate the DCOM connection

---

## SK-060 — Token Impersonation and Privilege Abuse

> type: tactic | category: privilege-escalation | category-label: Privilege Escalation | ttps: T1134.001, T1134.002
> author: jsmith | version: v1.0 | updated: 2026-04-25 | agents: tradecraft, detection

Detects token impersonation via SeImpersonatePrivilege abuse (Potato attacks — JuicyPotato, PrintSpoofer, RoguePotato) and explicit token creation via NtCreateToken. These techniques elevate from a service account to SYSTEM without exploiting a vulnerability — purely abusing legitimate Windows privilege semantics.

### Patterns
- EventCode 4672: sensitive privilege assigned to a non-admin user account — particularly SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege
- Sysmon EC1: `JuicyPotato.exe`, `PrintSpoofer.exe`, `RoguePotato.exe`, or generic named-pipe impersonation binaries
- Service process (IIS, SQL, mssql) spawning cmd.exe or PowerShell with elevated integrity level
- EventCode 4624 with LogonType=5 (service logon) immediately followed by LogonType=3 from the same host with SYSTEM token

### SPL
```spl
index=wineventlog EventCode=4672
| where match(PrivilegeList, "SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeTcbPrivilege")
| where NOT match(SubjectUserName, "(?i)(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|adm-|\$$)")
| table _time, host, SubjectUserName, PrivilegeList
```

### Exclusions
- IIS application pool accounts (IIS AppPool\*) — SeImpersonatePrivilege is required by design
- SQL Server service account (svc-sql) — requires SeImpersonatePrivilege for query execution
- CrowdStrike and Splunk service accounts — require elevated privileges for kernel-level operations

### Attack Paths
- T1078.003 | Valid Accounts: Local Accounts | high | SYSTEM token obtained via Potato attack enables full local control — attacker adds local admin account, disables firewall, and pivots using local credentials
- T1003.001 | LSASS Memory | high | SYSTEM-level access enables direct LSASS handle with PROCESS_ALL_ACCESS — complete credential extraction from all cached sessions on the host
- T1484.001 | Group Policy Modification | medium | If token impersonation is on a DC (via DCOM/WMI lateral), SYSTEM on DC enables GPO manipulation and mass deployment of persistence
