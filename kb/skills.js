// ════════════════════════════════════════════════════════════════════════════
// TRADECRAFT SKILLS REPOSITORY  —  kb/skills.js
// ════════════════════════════════════════════════════════════════════════════
// Analyst-authored hunting skills. Each skill is a reusable detection pattern
// with SPL, exclusions, and downstream attack-path context.
//
// skillType values:
//   'tactic'  — Generic MITRE ATT&CK technique knowledge, applies cross-org
//   'domain'  — Environment/org-specific: tuned to THIS network's topology,
//               tooling, naming conventions, and known-good baselines
//
// SOURCE OF TRUTH: kb/skills.md — edit that file to add or modify skills.
// This file is the inline fallback used when fetch() is unavailable (file://).
// At runtime, initKbTab() fetches skills.md and overwrites skillsData in-place.
// ════════════════════════════════════════════════════════════════════════════

const skillsData = [
  {
    id: 'SK-045', name: 'VMware vCenter Lateral Movement',
    skillType: 'domain',
    cat: 'lateral-movement', catLabel: 'Lateral Movement',
    ttps: ['T1078.001','T1550.003'],
    author: 'rmendez', version: 'v1.2', updated: '2026-05-14',
    agents: ['tradecraft','detection'],
    summary: 'VMware vCenter SSO token abuse and vSphere API lateral movement. Covers service-to-service auth anomalies, management plane enumeration, and host-jump via vMotion. Particularly useful for environments with mixed ESXi/vCenter topologies where standard endpoint telemetry is sparse.',
    patterns: [
      'vCenter SSO authentication events from non-standard service accounts outside VI-Admins OU',
      'vSphere API calls (vim.vm.guest.ProcessManager) outside approved maintenance windows',
      'Host-to-host connections on port 902/903 not correlated to a scheduled vMotion task',
      'PowerCLI execution on endpoints that are not in the VI-Admins or VMware-Ops groups',
    ],
    spl: `index=vcenter sourcetype=vmware:vcenter:event
| search EventType=UserLoginSessionEvent
| where NOT match(userName, "^svc-vi|^svc-vcenter|^vSphere")
| stats count by userName, ipAddress, datacenter`,
    exclusions: [
      'Scheduled vMotion tasks — validate against CMDB change-mgmt window',
      'svc-backup account during nightly backup window 01:00–04:00',
      'VMware Tools update process (vmtoolsd.exe) on managed VMs',
    ],
    attackPaths: [
      { ttp:'T1550.001', name:'Use Alt Auth: App Access Token', likelihood:'high', desc:'vSphere SSO tokens replayed to authenticate to additional VMs and management interfaces without re-authentication' },
      { ttp:'T1021.004', name:'Remote Services: SSH', likelihood:'medium', desc:'SSH to ESXi hosts directly using credentials harvested via vCenter API or management plane' },
      { ttp:'T1059.006', name:'Command & Scripting: Python', likelihood:'medium', desc:'PyVmomi library used to enumerate VM inventory, extract guest credentials, and pivot via vSphere API calls' },
    ],
  },
  {
    id: 'SK-038', name: 'Kerberoasting — Service Account FP Filter',
    skillType: 'domain',
    cat: 'credential-access', catLabel: 'Credential Access',
    ttps: ['T1558.003'],
    author: 'jsmith', version: 'v2.1', updated: '2026-04-29',
    agents: ['hypothesis','tradecraft','detection'],
    summary: 'Reduces false positives in Kerberoasting detection by excluding known-good SPN requesters — MSSQL, BackupExec, and scheduled task service accounts. Pre-loads CMDB-sourced SPN exclusion list and tunes the RC4 TGS threshold to org-specific baseline noise.',
    patterns: [
      'TGS-REQ for RC4 (0x17) tickets from interactive user sessions — not service accounts',
      'Bulk SPN enumeration: >5 unique SPNs requested within 60s from the same source IP',
      'TGS requests targeting accounts where pwdLastSet > 180 days (stale passwords)',
      'Kerberos pre-auth disabled flag set on account — high-value targeting indicator',
    ],
    spl: `index=wineventlog EventCode=4769 TicketEncryptionType=0x17
| where NOT match(ServiceName, "^krbtgt|^MSSQLSvc|^BackupExec|^WSMAN")
| stats count by AccountName, ServiceName, IpAddress
| where count > 3`,
    exclusions: [
      'BackupExec/BEService — high-volume SPN lookups expected during backup jobs',
      'MSSQLSvc/* — SQL service account auth is noisy by design',
      'WSMAN/* — WinRM service accounts in managed server OU',
    ],
    attackPaths: [
      { ttp:'T1078.002', name:'Valid Accounts: Domain Accounts', likelihood:'high', desc:'Cracked service account passwords enable direct authentication to servers the account legitimately accesses' },
      { ttp:'T1021.002', name:'Remote Services: SMB/Admin Shares', likelihood:'high', desc:'Service account credentials used for lateral movement to domain-joined hosts via SMB — particularly servers with SPN registrations' },
      { ttp:'T1558.001', name:'Golden Ticket', likelihood:'medium', desc:'If krbtgt hash obtained via DCSync (reachable once domain admin creds are cracked), forged TGTs grant unrestricted domain access' },
    ],
  },
  {
    id: 'SK-031', name: 'Firewall Anomaly — East-West Lateral Spread',
    skillType: 'domain',
    cat: 'lateral-movement', catLabel: 'Lateral Movement',
    ttps: ['T1021.001','T1021.002','T1570'],
    author: 'akowalski', version: 'v1.0', updated: '2026-03-11',
    agents: ['tradecraft','dataeng'],
    summary: 'Identifies abnormal east-west firewall flows indicative of lateral movement — new RDP/SMB paths between previously unconnected segments, or port scans from workstation-class assets. Built on a 30-day flow baseline; flags net-new paths not seen in prior observation window.',
    patterns: [
      'New RDP (3389) accept flows between workstation subnets with no prior 30d history',
      'SMB (445) accept from non-server sources within Corp-Workstations (10.10.x.x/16)',
      'Port sweep across >5 hosts from a single workstation-class asset within 120s',
      'ICMP echo sweep originating from a CMDB tier=3 (workstation) asset',
    ],
    spl: `index=firewall action=accept dest_port IN (445, 3389, 5985)
| where src_zone == dest_zone AND src_zone="Corp-Workstations"
| stats dc(dest_ip) as targets by src_ip
| where targets > 3`,
    exclusions: [
      'IT Support VLAN (10.10.50.0/24) — helpdesk RDP is expected and baselined',
      'SCCM server (10.0.5.20) — SMB to all workstations during patch cycles',
    ],
    attackPaths: [
      { ttp:'T1003.001', name:'LSASS Memory', likelihood:'high', desc:'Credential access on newly reached host to harvest hashes for the next lateral hop — standard post-movement step' },
      { ttp:'T1570', name:'Lateral Tool Transfer', likelihood:'high', desc:'Attacker tooling deployed to compromised workstations via SMB admin shares once lateral path is established' },
      { ttp:'T1049', name:'System Network Connections Discovery', likelihood:'medium', desc:'Network enumeration from beachhead host to map additional targets and identify high-value systems to pivot toward' },
    ],
  },
  {
    id: 'SK-029', name: 'LSASS Credential Dumping — EDR Evasion Variants',
    skillType: 'tactic',
    cat: 'credential-access', catLabel: 'Credential Access',
    ttps: ['T1003.001'],
    author: 'rmendez', version: 'v3.0', updated: '2026-05-01',
    agents: ['tradecraft','detection','validation'],
    summary: 'Covers modern LSASS dump evasion techniques that bypass standard process-access rules — handle duplication via NtDuplicateObject, direct syscall stubs, and PPL bypass using BYOVD. Derived from red team debrief notes and CrowdStrike incident data across three engagements.',
    patterns: [
      'NtReadVirtualMemory calls to lsass.exe from non-AV/EDR processes (Sysmon EC10)',
      'Shadow copy creation (vssadmin) immediately followed by an LSASS-sized file read',
      'Handle duplication to lsass via NtDuplicateObject from an unsigned DLL',
      'comsvcs.dll MiniDump invoked via wmic.exe or cmd.exe — fileless variant',
    ],
    spl: `index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where NOT match(SourceImage, "(?i)(defender|MsMpEng|crowdstrike|CSFalcon|carbon)")
| table _time, SourceImage, GrantedAccess, CallTrace`,
    exclusions: [
      'CrowdStrike sensor (CSFalconService.exe) — legitimate LSASS inspection by EDR',
      'Windows Defender (MsMpEng.exe) — AV scanning access is expected',
    ],
    attackPaths: [
      { ttp:'T1550.002', name:'Pass-the-Hash', likelihood:'high', desc:'NTLM hashes extracted from LSASS enable lateral movement to other Windows hosts without cracking the password' },
      { ttp:'T1078.002', name:'Valid Accounts: Domain Accounts', likelihood:'high', desc:'Clear-text credentials (if present in LSASS memory) enable direct domain authentication and privilege escalation' },
      { ttp:'T1003.006', name:'DCSync', likelihood:'medium', desc:'Domain admin credentials obtained via LSASS give access to DCSync — extracts all domain hashes from AD replication' },
    ],
  },
  {
    id: 'SK-022', name: 'DNS Beaconing Pattern Recognition',
    skillType: 'tactic',
    cat: 'c2', catLabel: 'Command & Control',
    ttps: ['T1071.004','T1568.002'],
    author: 'jsmith', version: 'v1.3', updated: '2026-02-18',
    agents: ['hypothesis','tradecraft'],
    summary: 'Statistical approach to identifying C2 DNS beaconing using periodicity scoring, Shannon entropy on query names, and domain age gating. Tuned against org-specific resolver noise — reduces FP rate to <3% on known-good traffic. Catches JA3-agnostic C2 that evades TLS inspection.',
    patterns: [
      'Query interval coefficient of variation < 0.1 over 20+ requests (high periodicity)',
      'NXDOMAIN rate > 40% from a single source within a 10-minute window',
      'Shannon entropy of queried domain labels > 3.5 (DGA indicator)',
      'Domain registered < 30 days with MX record present but no prior org traffic',
    ],
    spl: `index=dns
| stats count, stdev(interval) as sd, avg(interval) as avg_i by src_ip, query
| eval cv=sd/avg_i
| where cv < 0.1 AND count > 20
| sort - count`,
    exclusions: [
      'Windows Update / Microsoft CDN domains (*.windowsupdate.com, *.microsoft.com)',
      'Known telemetry endpoints listed in org threat-intel exclusion feed',
    ],
    attackPaths: [
      { ttp:'T1041', name:'Exfiltration Over C2 Channel', likelihood:'high', desc:'Established DNS tunnel used for data exfiltration — low-bandwidth but highly covert; files chunked into query labels' },
      { ttp:'T1105', name:'Ingress Tool Transfer', likelihood:'high', desc:'Additional implant stages or tooling downloaded via DNS channel using TXT or A record responses as transport' },
      { ttp:'T1071.001', name:'Application Layer Protocol: Web', likelihood:'medium', desc:'Pivot from DNS C2 to HTTP/S for higher-bandwidth operations once initial foothold is confirmed stable' },
    ],
  },
  {
    id: 'SK-017', name: 'PowerShell Obfuscation Fingerprinting',
    skillType: 'tactic',
    cat: 'execution', catLabel: 'Execution',
    ttps: ['T1059.001','T1027'],
    author: 'akowalski', version: 'v2.2', updated: '2026-01-30',
    agents: ['tradecraft','detection'],
    summary: 'Identifies PowerShell obfuscation patterns including encoding stacking, backtick insertion, character substitution, and environment variable concatenation. Covers both classic Invoke-Obfuscation output and manual obfuscation seen in living-off-the-land intrusions.',
    patterns: [
      'CommandLine length > 500 chars with >30% special characters',
      'Base64 payload nested inside -EncodedCommand (double-encoded)',
      'Backtick insertion splitting execution keywords: i`e`x, `n`e`t, In`voke',
      'String concatenation constructing Invoke-Expression or iex via Join/Format',
    ],
    spl: `index=sysmon EventCode=1 (Image="*powershell*" OR Image="*pwsh*")
| eval cmd_len=len(CommandLine)
| where cmd_len > 500 OR match(CommandLine, "(?i)i\`|iex|EncodedCommand.+EncodedCommand")
| table _time, host, user, CommandLine`,
    exclusions: [
      'SCCM/ConfigMgr scripts — must be code-signed and originate from 10.0.5.20',
      'Legitimate admin scripts under C:\\Windows\\CCM\\ or C:\\Program Files\\...',
    ],
    attackPaths: [
      { ttp:'T1055', name:'Process Injection', likelihood:'high', desc:'Obfuscated PS commonly delivers shellcode injected into legitimate Windows processes — explorer.exe, svchost.exe' },
      { ttp:'T1105', name:'Ingress Tool Transfer', likelihood:'medium', desc:'Obfuscated PS stages download additional payloads from C2 — second-stage implants, credential dumpers, lateral movement tools' },
      { ttp:'T1003.001', name:'LSASS Memory', likelihood:'medium', desc:'Credential dumping typically follows once execution capability is established — obfuscated PS is often the delivery mechanism' },
    ],
  },
];

// Skills pending analyst review before promotion to skillsData.
// Append drafts here after submitting via the Propose Edit form.
const skillDrafts = [
  { id:'SK-007-draft', name:'Pass-the-Hash via SMB (wmiexec pattern)', cat:'lateral-movement', author:'rmendez', ts:'2026-05-19 14:32', status:'pending' },
  { id:'SK-008-draft', name:'Living-off-the-Land Persistence via Scheduled Tasks', cat:'persistence', author:'alice', ts:'2026-05-20 09:17', status:'pending' },
];
