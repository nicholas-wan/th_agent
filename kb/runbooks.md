# TTP Runbooks

Per-technique hunt guides — one entry per MITRE ATT&CK technique. Each runbook covers adversary evidence indicators, hunting SPL, prior hunt notes from this environment, and known false positives. The Hypothesis Agent loads these at hunt time via `get_runbook(ttp_id)`.

To add a new runbook, copy any section below, paste it before the last `---`, and fill in the fields. The section heading must start with `## T` followed by the technique ID.

Evidence severity levels: `crit` · `high` · `info`

---

## T1003.001 — OS Credential Dumping: LSASS Memory

> tactic: Credential Access

Adversaries access the LSASS process to extract plaintext passwords, hashes, and Kerberos tickets. Common tools include Mimikatz, ProcDump, and Task Manager.

### Evidence
- crit | Process handle to `lsass.exe` with access mask `0x1fffff` (PROCESS_ALL_ACCESS) from a non-AV/EDR source image.
- crit | `sekurlsa::logonpasswords` or `sekurlsa::wdigest` in command-line arguments — direct Mimikatz invocation.
- high | `MiniDumpWriteDump` API calls targeting `lsass.exe` PID from `procdump.exe`, `rundll32.exe comsvcs.dll MiniDump`, or custom loaders.
- high | Driver load of `mimidrv.sys` or unsigned kernel driver interacting with LSASS.
- info | Check Sysmon Event ID 10 (ProcessAccess) for `TargetImage = lsass.exe` with `GrantedAccess != 0x1410` (standard AV pattern).

### Queries

#### Sysmon Event 10 — suspicious LSASS handle
```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
  NOT SourceImage IN ("*\\MsMpEng.exe","*\\CylanceSvc.exe","*\\SentinelAgent.exe")
| eval suspicious=if(match(GrantedAccess,"0x1fffff|0x1410ff|0x143a"),1,0)
| where suspicious=1
| stats count by SourceImage, GrantedAccess, host, _time
| sort -count
```

#### comsvcs.dll MiniDump LOLBin
```spl
index=windows EventCode=4688
  CommandLine="*comsvcs*" CommandLine="*MiniDump*"
| table _time, host, user, CommandLine
```

### Hunt Notes
- TH-2026-038 | 2026-04-12 | Marcus Webb | Confirmed rundll32.exe comsvcs.dll MiniDump on WIN-DC01. Dump written to C:\Windows\Temp\lsass.dmp then exfil via SMB. Added hash of dump file to threat intel.
- TH-2025-091 | 2025-11-03 | Alice Chen | ProcDump blocked by EDR but attacker pivoted to Task Manager manual dump. Recommend monitoring \AppData\Local\Temp for .dmp files >10MB.

### False Positives
- Windows Defender and CrowdStrike routinely open LSASS with 0x1410 access — filter by SourceImage.
- Some vulnerability scanners and backup agents (Veeam, BackupExec) legitimately open LSASS. Baseline and exclude by hash.

---

## T1078.002 — Valid Accounts: Domain Accounts

> tactic: Initial Access / Persistence / Privilege Escalation

Adversaries use compromised domain credentials to authenticate to systems and services, blending with legitimate user activity. Volt Typhoon heavily favours this technique to maintain persistence without dropping malware.

### Evidence
- crit | Domain account authenticating from an unusual source host — IP not in user's normal subnet or geolocation anomaly.
- crit | Off-hours logon (Event 4624/4769) from a service account that normally only runs scheduled tasks.
- high | Single account performing lateral movement to ≥5 hosts within a 30-minute window (use 4769 TGS requests as proxy).
- info | Cross-reference with VPN/proxy logs — Volt Typhoon frequently accesses domain accounts from SOHO-router-proxied IPs (AS numbers: small ISPs, residential blocks).

### Queries

#### Off-hours domain logon anomaly
```spl
index=security EventCode=4624 Logon_Type=3
| eval hour=tonumber(strftime(_time,"%H")), dow=strftime(_time,"%A")
| where (hour < 6 OR hour > 21) AND dow!="Saturday" AND dow!="Sunday"
| stats dc(host) as hosts_touched, values(host) as hosts by user, src_ip
| where hosts_touched > 2
| sort -hosts_touched
```

#### Single account TGS-REQ spike (lateral movement)
```spl
index=windows EventCode=4769 Ticket_Encryption_Type=0x17
  NOT Service_Name IN ("krbtgt","*$")
| bucket _time span=30m
| stats dc(Service_Name) as spns, values(Service_Name) as services by Account_Name, Client_Address, _time
| where spns > 8
| sort -spns
```

### Hunt Notes
- TH-2026-038 | 2026-04-11 | Marcus Webb | jsmith account used from 3 different source IPs overnight. One IP resolved to a compromised SOHO router in AS63949. Single-hop threshold set at 14 hosts before escalation.

### False Positives
- IT admin accounts legitimately log in after hours during maintenance windows — maintain a scheduled-maintenance allowlist.
- Service accounts running scripts will show bulk TGS requests; exclude by SPN pattern (SCCM, BackupExec, SQL).

---

## T1570 — Lateral Tool Transfer

> tactic: Lateral Movement

Adversaries transfer tools or malware to remote systems via SMB, WMI, RDP clipboard, or LOLBins. Often follows valid-account abuse to stage additional payloads.

### Evidence
- crit | Executable written to `\\host\ADMIN$\Temp\` or `\\host\C$\Windows\Temp\` by a user account (not a known deployment tool).
- high | SMB file write of `.exe`, `.dll`, or `.ps1` followed within 60s by a Service Control Manager event (Event 7045) on the target host.
- info | Correlate Sysmon Event 11 (FileCreate) on target with Sysmon Event 3 (NetworkConnect) on source — timestamp delta <5s is a strong indicator.

### Queries

#### SMB write to admin share → service install
```spl
index=windows EventCode=7045
| eval install_time=_time
| join host [search index=security EventCode=5145 Share_Name="\\*\\ADMIN$" Object_Type=File Accesses="WriteData*"
  | eval write_time=_time | table host, write_time, Relative_Target_Name, Account_Name]
| eval delta=install_time-write_time
| where delta>=0 AND delta<120
| table _time, host, Account_Name, Relative_Target_Name, Service_Name, delta
```

### Hunt Notes
- TH-2026-038 | 2026-04-12 | Marcus Webb | Tool staged to ADMIN$ share on 14 hosts. File was a renamed copy of netcat (nc64.exe → svchost.exe). Hash: d41d8cd98f00b204e9800998ecf8427e.

### False Positives
- SCCM and Intune push executables to admin shares constantly — exclude by source account (svc-sccm, svc-intune).
- Backup agents write to ADMIN$ as part of VSS operations — correlate with backup schedule.

---

## T1053.005 — Scheduled Task/Job: Scheduled Task

> tactic: Execution / Persistence / Privilege Escalation

Adversaries create scheduled tasks to execute malicious code repeatedly or at specific times. A common persistence mechanism on Windows requiring only user-level privilege with the right API calls.

### Evidence
- crit | Scheduled task created by `schtasks.exe /create` running from a non-standard parent (e.g. `powershell.exe`, `wscript.exe`, `mshta.exe`).
- high | Task XML written directly to `C:\Windows\System32\Tasks\` via a file-write API (bypasses schtasks.exe logging).
- info | Event 4698 (task created) + 4702 (task updated) in the Security log. Correlate with the task's Action element — look for encoded PowerShell or paths outside `C:\Windows\System32`.

### Queries

#### Suspicious scheduled task creation
```spl
index=windows EventCode=4698
| spath input=Task_Content output=task_action path=Task.Actions.Exec.Command
| where match(task_action,"powershell|cmd|wscript|mshta|regsvr32|rundll32")
   OR match(task_action,"\\AppData|\\Temp|\\Users\\Public")
| table _time, host, user, Task_Name, task_action
```

### Hunt Notes
- TH-2025-091 | 2025-11-04 | Alice Chen | Task created under SYSTEM context using COM object ITaskService — bypassed schtasks.exe. No 4698 event fired; detected via Sysmon file-create in Tasks directory.

### False Positives
- SCCM ConfigMgr creates tasks named ConfigMgr_* — exclude by Task_Name pattern.
- Software update agents (Chrome, Teams, Adobe) create tasks in user AppData — baseline by publisher signature.

---

## T1003 — OS Credential Dumping

> tactic: Credential Access

Parent technique covering all credential dumping sub-techniques. See T1003.001 (LSASS) for the most common variant.

### Evidence
- info | Start with T1003.001 (LSASS) for Windows environments. Also check T1003.002 (SAM), T1003.003 (NTDS) for domain controller targeting.

### Queries

### Hunt Notes

### False Positives

---

## T1003.006 — DCSync

> tactic: Credential Access

Adversary mimics a Domain Controller using the MS-DRSR protocol to replicate all credential hashes from Active Directory. Requires `DS-Replication-Get-Changes-All` rights. Mimikatz `lsadump::dcsync` and Impacket `secretsdump.py` are the primary tools. Only DCs and Azure AD Connect have this right in a healthy domain.

### Evidence
- crit | EventCode 4662 with `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes-All) from a non-DC subject account.
- crit | EventCode 4662 with `{19195a5b-6da0-11d0-afd3-00c04fd930c9}` (DS-Replication-Get-Changes) originating from a workstation IP.
- high | Volume spike: >10 EventCode 4662 events from the same non-DC account within 60 seconds.
- info | Correlate source IP against asset inventory — any non-DC host performing replication is high-confidence.

### Queries

#### DCSync from non-DC account
```spl
index=wineventlog EventCode=4662
| search Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
| where NOT match(SubjectUserName, "(?i)^WIN-DC|MSOL_|ADSync|\$$")
| stats count, values(SubjectDomainName) as domain by SubjectUserName, host
| sort - count
```

#### Replication spike — bulk hash extraction indicator
```spl
index=wineventlog EventCode=4662
| bucket _time span=60s
| stats count by SubjectUserName, _time
| where count > 10
| where NOT match(SubjectUserName, "(?i)^WIN-DC|\$$")
| sort - count
```

### Hunt Notes
- TH-2026-041 | 2026-04-27 | Marcus Webb | DCSync attempt blocked by CrowdStrike on WIN-WS041 using jsmith credentials. jsmith is not in any replication-rights group. Likely credential reuse from LSASS dump. Escalated to IR.
- TH-2026-038 | 2026-04-13 | Marcus Webb | Post-compromise DCSync confirmed. All domain hashes presumed extracted. krbtgt double-reset performed. Golden Ticket window: ~4h between dump and detection.

### False Positives
- WIN-DC01 and WIN-DC02 — legitimate AD replication (filter by SubjectUserName ending in $).
- MSOL_* and ADSync accounts — Azure AD Connect delta sync fires every 30 min.
- Vulnerability scanners running BloodHound collection can trigger partial replication events — validate against change ticket.

---

## T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

> tactic: Credential Access

Adversary requests TGS tickets for service accounts with registered SPNs, then cracks the RC4-encrypted ticket offline. Requires no special privileges — any domain-authenticated user can request TGS tickets. Stale service account passwords (>90 days) are the primary target.

### Evidence
- crit | EventCode 4769 (TGS request) with `TicketEncryptionType=0x17` (RC4-HMAC) from an interactive user session — RC4 is downgraded by attackers to enable faster offline cracking.
- high | >5 unique SPN requests from a single source IP within 60 seconds — bulk enumeration using Rubeus or Impacket GetUserSPNs.
- high | TGS requests targeting accounts with `pwdLastSet` > 90 days — stale service account passwords are prioritised for cracking.
- info | Absence of matching Kerberos pre-auth events (4768) before a TGS batch suggests roasting without interactive logon.

### Queries

#### RC4 TGS requests from interactive sessions
```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| where NOT match(Service_Name, "(?i)^krbtgt|^\$$|^host\/|^cifs\/")
| stats count, dc(Service_Name) as unique_spns, values(Service_Name) as spns by Account_Name, Client_Address
| where count > 3
| sort - unique_spns
```

#### Bulk SPN enumeration — Rubeus/GetUserSPNs pattern
```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| bucket _time span=60s
| stats dc(Service_Name) as spn_count by Account_Name, Client_Address, _time
| where spn_count > 5
| sort - spn_count
```

### Hunt Notes
- TH-2026-041 | 2026-04-27 | Marcus Webb | Kerberoasting attempt from WIN-WS041 (jsmith session). 9 unique SPNs requested in 14s — svc-backup and svc-sql both targeted. svc-backup password age: 180 days. Forced password reset on all targeted service accounts.
- TH-2025-091 | 2025-11-05 | Alice Chen | Roasting not detected during initial hunt — only found during post-incident review of Security log. Consider alerting on burst of >3 unique RC4 TGS from non-service accounts.

### False Positives
- BackupExec and legacy SQL applications that enforce RC4 — validate with app team and create per-SPN exclusions.
- SCCM service discovery generates TGS requests during hardware inventory — exclude svc-sccm source.
- Legitimate admin bulk SPN verification from JUMP-01 (adm-itops) — suppress by source IP 10.0.9.10 with valid change ticket.

---

## T1059.001 — Command and Scripting Interpreter: PowerShell

> tactic: Execution

PowerShell is the most heavily abused scripting engine in Windows intrusions. Adversaries use it for initial access payloads, lateral movement, credential dumping, and C2 communication. Encoded commands (`-EncodedCommand`), download-cradles (`IEX (New-Object Net.WebClient).DownloadString`), and AMSI bypass are the primary indicators.

### Evidence
- crit | `powershell.exe` or `pwsh.exe` with `-EncodedCommand` argument where the decoded payload contains `IEX`, `Invoke-Expression`, or network methods.
- crit | PowerShell network connection (EventCode 3) to a non-Microsoft external IP within 30 seconds of process creation — download cradle pattern.
- high | `Add-MpPreference -ExclusionPath` or `Set-MpPreference -DisableRealtimeMonitoring` — Defender bypass.
- high | Parent process is a document viewer (Word, Excel, PDF reader), browser, or email client — phishing delivery.
- info | PowerShell ScriptBlock logging (EventCode 4104) capturing runtime-deobfuscated payloads — enable `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`.

### Queries

#### Encoded command with network activity
```spl
index=sysmon EventCode=1 (Image="*powershell.exe" OR Image="*pwsh.exe")
  CommandLine="*-EncodedCommand*"
| eval decoded=base64decode(mvindex(split(CommandLine,"-EncodedCommand "),1))
| where match(decoded,"(?i)(iex|invoke-expression|downloadstring|webclient|Net\.WebClient)")
| table _time, host, User, CommandLine, decoded
```

#### PowerShell spawned from suspicious parent
```spl
index=sysmon EventCode=1 (Image="*powershell.exe" OR Image="*pwsh.exe")
| where match(ParentImage, "(?i)(WINWORD|EXCEL|OUTLOOK|AcroRd32|chrome|firefox|iexplore|wscript|mshta)")
| table _time, host, User, ParentImage, CommandLine
```

#### ScriptBlock log — runtime deobfuscation
```spl
index=wineventlog EventCode=4104
| where match(ScriptBlock_Text, "(?i)(invoke-mimikatz|invoke-expression|downloadstring|shellcode|bypass|amsi)")
| table _time, host, Path, ScriptBlock_Text
```

### Hunt Notes
- TH-2026-038 | 2026-04-12 | Marcus Webb | Encoded PS payload decoded to a Cobalt Strike stager. Base64 within `-EncodedCommand` — double-encoded. Second layer was a compressed GZIP blob expanded with `[IO.Compression.DeflateStream]`. AMSI bypass used prior to CS load.
- TH-2025-091 | 2025-11-03 | Alice Chen | PS download cradle to pastebin-hosted payload. ScriptBlock logging caught deobfuscated content. Ensure 4104 is enabled — it was not enabled on 40% of endpoints during this hunt.

### False Positives
- SCCM configuration scripts — all signed and originating from svc-sccm on 10.0.5.20. Suppress by source account + parent = ccmexec.exe.
- Azure AD Connect (ADSync) PS modules at sync intervals — suppress by account MSOL_* from SPLUNK-ES.
- CrowdStrike RTR PowerShell sessions — `csfalconservice.exe` parent, suppress by SourceImage.

---

## T1547.001 — Boot/Logon Autostart: Registry Run Keys / Startup Folder

> tactic: Persistence / Privilege Escalation

Adversaries write to HKLM\SOFTWARE\...\Run, HKCU\...\Run, or the Startup folder to execute code at user logon or system boot. Requires minimal privilege for HKCU variants. Sysmon EventCode 13 (RegistryEvent) provides the highest-fidelity telemetry.

### Evidence
- crit | Sysmon EC13 write to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` from a process in `%TEMP%`, `%APPDATA%`, or `C:\Users\Public\`.
- high | Sysmon EC13 write to `Winlogon\Userinit` or `Winlogon\Shell` — can hijack the entire user session.
- high | File created in `C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` that is not a known application shortcut.
- info | Compare Run key values against CMDB software baseline — any entry pointing to a hash not in the approved software list warrants investigation.

### Queries

#### Run key write from suspicious process
```spl
index=sysmon EventCode=13
| where match(TargetObject, "(?i)(\\CurrentVersion\\Run|\\CurrentVersion\\RunOnce|\\Winlogon\\Userinit|\\Winlogon\\Shell)")
| where NOT match(Image, "(?i)(msiexec|setup|install|OfficeC2R|OneDrive|Teams|Chrome|Slack|ccmexec|svchost)")
| where NOT match(Image, "(?i)^C:\\\\Program Files|^C:\\\\Windows\\\\System32")
| table _time, host, User, Image, TargetObject, Details
```

#### Startup folder drop
```spl
index=sysmon EventCode=11
| where match(TargetFilename, "(?i)\\\\Start Menu\\\\Programs\\\\Startup\\\\")
| where NOT match(Image, "(?i)(msiexec|setup|installer|OneDrive|Teams)")
| table _time, host, User, Image, TargetFilename
```

### Hunt Notes
- TH-2025-091 | 2025-11-04 | Alice Chen | Run key pointing to `%APPDATA%\Microsoft\Edge\msedge_updater.exe` — masquerading as Edge updater. Binary was an unsigned PE with CS beacon embedded. Path chosen to evade `C:\Program Files` signing checks.

### False Positives
- OneDrive, Teams, Slack, Chrome — all write Run keys during user-context installation. Baseline by signed PE hash.
- SCCM software deployment via ccmexec.exe may write Run keys for managed applications.
- Windows Update orchestrator (`USOCoreWorker.exe`) writes RunOnce entries — suppress by Image path and signed hash.

---

## T1047 — Windows Management Instrumentation

> tactic: Execution / Lateral Movement

WMI provides remote command execution capabilities abused by adversaries to run code on remote hosts without dropping files. `wmic /node:` and `Invoke-WmiMethod` are the common invocation methods. WMI event subscriptions (T1546.003) provide fileless persistence that survives reboots and evades many EDR file-based detections.

### Evidence
- crit | `WmiPrvSE.exe` spawning `cmd.exe`, `powershell.exe`, `wscript.exe`, or any LOLBin — indicates successful remote WMI execution.
- high | EventCode 4648 (explicit credential logon) followed within 5s by WMI process creation on target — credential-reuse lateral movement.
- high | WMI permanent event subscription creation (EventCode 5857/5860/5861) by a non-admin account — fileless persistence.
- info | Network connection to port 135 (DCOM endpoint mapper) followed by ephemeral RPC port from workstation-class asset.

### Queries

#### WmiPrvSE spawning execution chain
```spl
index=sysmon EventCode=1 ParentImage="*WmiPrvSE.exe"
| where match(Image, "(?i)(cmd\.exe|powershell|wscript|cscript|mshta|certutil|bitsadmin|regsvr32)")
| table _time, host, User, Image, CommandLine, ParentCommandLine
```

#### WMI event subscription (fileless persistence)
```spl
index=wineventlog (EventCode=5857 OR EventCode=5860 OR EventCode=5861)
| stats count by host, User, OperationName
| where OperationName IN ("EventFilter", "EventConsumer", "FilterToConsumerBinding")
| sort - count
```

#### Remote WMI from workstation to DC/server
```spl
index=sysmon EventCode=3 DestinationPort=135
| where match(SourceIp, "^10\.0\.3\.")
| where match(DestinationIp, "^10\.0\.(1|2)\.")
| stats count, values(DestinationIp) as targets by SourceIp, User
| where count > 2
```

### Hunt Notes
- TH-2026-038 | 2026-04-12 | Marcus Webb | WMI used to execute Cobalt Strike stager on 6 Server Farm hosts from WIN-WS041. Command: `wmic /node:<target> process call create "cmd.exe /c powershell -enc <b64>"`. Appeared as WmiPrvSE→cmd.exe in Sysmon. No 4688 events on target — WMI bypassed process audit on older policy.

### False Positives
- SCCM WMI inventory queries (parent chain: ccmexec.exe → WmiPrvSE → splunkd-style query) — exclude by ParentCommandLine containing `CCM_Invoke`.
- Splunk WMI inputs collect data via WmiPrvSE — suppress by SourceIp = 10.0.5.20.
- Antivirus WMI namespace scanning during on-demand scan — whitelist by known AV signed binary hash.

---

## T1490 — Inhibit System Recovery

> tactic: Impact

Adversaries delete Volume Shadow Copies and modify boot recovery settings to prevent restoration after ransomware encryption. This is a near-universal pre-encryption step in modern ransomware (LockBit 3.0, BlackCat/ALPHV, Akira). Detection window is short — typically 1–10 minutes before encryption begins.

### Evidence
- crit | `vssadmin.exe delete shadows /all` or `wmic shadowcopy delete` — immediate ransomware precursor. Treat as active incident.
- crit | `bcdedit.exe /set {default} recoveryenabled No` or `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures` — disabling Windows Recovery Environment.
- high | `wbadmin delete catalog -quiet` — removes Windows Server Backup catalog.
- high | Multiple hosts showing shadow deletion within a 5-minute window — ransomware lateral movement underway.
- info | Process tree: often spawned from `cmd.exe` or `powershell.exe` parent with high-entropy name in `C:\Windows\Temp\` or `C:\Users\Public\`.

### Queries

#### Shadow deletion — critical alert
```spl
index=sysmon EventCode=1
| where (match(Image,"(?i)vssadmin") AND match(CommandLine,"(?i)delete"))
  OR (match(Image,"(?i)wmic") AND match(CommandLine,"(?i)shadowcopy.+delete"))
  OR (match(Image,"(?i)wbadmin") AND match(CommandLine,"(?i)delete.+catalog"))
| table _time, host, User, Image, CommandLine, ParentImage, ParentCommandLine
| sort - _time
```

#### Boot recovery tampering
```spl
index=sysmon EventCode=1 Image="*bcdedit.exe"
| where match(CommandLine, "(?i)(recoveryenabled.+No|bootstatuspolicy.+ignore)")
| table _time, host, User, CommandLine, ParentImage
```

#### Multi-host shadow deletion — ransomware spread
```spl
index=sysmon EventCode=1
| where match(Image,"(?i)vssadmin|wmic") AND match(CommandLine,"(?i)delete")
| bucket _time span=5m
| stats dc(host) as hosts_affected, values(host) as affected_list by _time
| where hosts_affected > 2
```

### Hunt Notes
- TH-2026-038 | 2026-04-13 | Marcus Webb | Shadow deletion NOT observed — ransomware deployment was interdicted during lateral movement phase. Recommend creating a real-time alert rule in Splunk ES for this query, not just a hunt.

### False Positives
- svc-backup deleting old shadow copies post-backup to manage disk space — must occur from scheduled task on Server Farm hosts only, not workstations. Correlate with backup window 01:00–04:00.
- No other known legitimate use of `vssadmin delete shadows /all` in this environment. Any other instance = treat as incident.

---

## T1071.004 — Application Layer Protocol: DNS

> tactic: Command & Control

Adversaries use DNS queries as a covert C2 channel. Data is encoded in subdomain labels (e.g. `aGVsbG8=.c2domain.com`). DNS-over-HTTPS (DoH) is increasingly used to bypass inspection. Detection relies on statistical analysis of query patterns — periodicity, entropy, and NXDOMAIN rates.

### Evidence
- crit | Query interval coefficient of variation (CV) < 0.1 over 20+ requests — machine-generated beaconing pattern, not human browsing.
- high | Shannon entropy of subdomain label > 3.5 — DGA or encoded data in query name.
- high | NXDOMAIN rate > 40% from a single source IP within 10 minutes — DGA domain rotation or failed C2 infrastructure.
- high | Long TXT record responses (>200 bytes) from a newly registered domain — data exfiltration via DNS TXT.
- info | DNS queries to domains registered < 30 days with no prior org history — infrastructure hunting indicator.

### Queries

#### Beaconing periodicity detection
```spl
index=dns
| bin _time span=1s
| stats count by src_ip, query, _time
| stats count, stdev(_time) as sd, avg(_time) as avg_t by src_ip, query
| eval cv=sd/avg_t
| where cv < 0.1 AND count > 20
| sort cv
```

#### High-entropy subdomain (DGA / DNS tunnel)
```spl
index=dns
| eval label=mvindex(split(query,"."),0)
| eval entropy=if(len(label)>8, 1, 0)
| where entropy=1
| where NOT match(query, "(?i)(microsoft|windows|google|akamai|cloudflare|amazonaws)")
| stats count, values(query) as queries by src_ip
| where count > 5
```

#### NXDOMAIN storm
```spl
index=dns reply_code=NXDOMAIN
| bucket _time span=10m
| stats count by src_ip, _time
| where count > 50
| sort - count
```

### Hunt Notes
- TH-2026-041 | 2026-04-27 | Marcus Webb | DNS beaconing from WIN-WS041 to `*.update-cdn[.]net` — 47 queries with CV=0.04 (15-second interval). Domain registered 8 days prior. Blocked at perimeter. IOC added: update-cdn[.]net (TI feed + DNS sinkhole).

### False Positives
- Windows Update and Microsoft telemetry generate periodic DNS queries — suppress `*.microsoft.com`, `*.windowsupdate.com`, `*.msftncsi.com`.
- Teams and Outlook polling (very regular intervals) — suppress by known Microsoft CDN domains.
- Antivirus cloud lookups — suppress by known vendor domains (CrowdStrike: `*.crowdstrike.com`).

---

## T1550.002 — Use Alternate Authentication Material: Pass-the-Hash

> tactic: Lateral Movement / Defense Evasion

Adversary uses a captured NTLM hash to authenticate to remote services without knowing the plaintext password. Detectable by correlating NTLMv2 network logons (EventCode 4624 LogonType=3, AuthPackage=NTLM) against the absence of an interactive session on the source host. PtH appears as normal network logon activity — low noise.

### Evidence
- crit | EventCode 4624 LogonType=3 with `AuthenticationPackageName=NTLM` and `LmPackageName=NTLM V2` from a workstation-class source to a Domain Controller — DCs should only accept Kerberos from workstations.
- high | Single user authenticating via NTLM to >3 hosts within 10 minutes from the same source IP — lateral movement sweep.
- high | No corresponding EventCode 4648 (explicit credential use) on source host for the same session — hash replay rather than entered credential.
- info | NTLM auth from a host where the user has no active interactive session (EventCode 4634 already logged) — account is not locally logged in.

### Queries

#### NTLM auth from workstation to DC (anomalous)
```spl
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
| where match(IpAddress, "^10\.0\.3\.")
| where match(host, "(?i)WIN-DC")
| where NOT match(TargetUserName, "(?i)ANONYMOUS|SYSTEM|\$$")
| table _time, TargetUserName, IpAddress, host, WorkstationName
```

#### Multi-hop PtH — lateral spread
```spl
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
| where NOT match(TargetUserName, "(?i)ANONYMOUS|SYSTEM|\$$")
| where NOT match(IpAddress, "^10\.0\.(5|9)\.")
| stats dc(host) as dest_count, values(host) as destinations by TargetUserName, IpAddress
| where dest_count > 2
| sort - dest_count
```

### Hunt Notes
- TH-2026-041 | 2026-04-27 | Marcus Webb | PtH from WIN-WS041 using jsmith NTLM hash. 14 hosts reached via NTLMv2 lateral movement. Hash sourced from LSASS dump earlier in same session. EventCode 4624 LogonType=3 was the first indicator — no corresponding 4648 on source.
- TH-2026-038 | 2026-04-11 | Marcus Webb | PtH to ADMIN$ on 6 Server Farm hosts using svc-backup hash. Service account never has interactive sessions — absence of 4624 LogonType=2 on source was the FP elimination step.

### False Positives
- Legacy applications that require NTLM auth (older Java apps, some monitoring tools) — create per-application allowlist in CMDB.
- Printer servers using NTLM for client authentication — scope suppression to printer subnet (10.0.7.0/24 if applicable).
- Initial domain join process uses NTLM — suppressed by machine account name (ending in $).

---

## T1562.001 — Impair Defenses: Disable or Modify Tools

> tactic: Defense Evasion

Adversaries disable or tamper with security software (EDR, AV, logging) before conducting high-noise operations such as credential dumping, ransomware deployment, or mass lateral movement. In CORP, the critical controls are CrowdStrike Falcon (CSFalconService), Sysmon (SysmonDrv), and the Windows Event Log service.

### Evidence
- crit | Service state change to `Stopped` or `Disabled` for `CSFalconService`, `SysmonDrv`, or `EventLog` (EventCode 7036/7045).
- crit | `wevtutil.exe cl Security` or `wevtutil.exe cl Microsoft-Windows-Sysmon/Operational` — log clearing immediately before or after this is presumptive evidence of an active intrusion.
- high | Registry deletion or modification under `HKLM\SYSTEM\CurrentControlSet\Services\CSAgent` or `SysmonDrv`.
- high | EventCode 4719 (audit policy change) removing categories: Logon, Account Logon, Object Access.
- info | `sc.exe config <service> start= disabled` or PowerShell `Set-Service -StartupType Disabled` targeting security services.

### Queries

#### Security service stopped or disabled
```spl
index=wineventlog (EventCode=7036 OR EventCode=7045)
| where match(ServiceName, "(?i)(CSFalcon|SysmonDrv|WinDefend|EventLog|SecurityHealth)")
| where match(Message, "(?i)(stopped|disabled|deleted)")
| table _time, host, ServiceName, Message
```

#### Event log clearing
```spl
index=sysmon EventCode=1 Image="*wevtutil.exe"
| where match(CommandLine, "(?i)(cl |clear-log)")
| table _time, host, User, CommandLine, ParentImage, ParentCommandLine
```

#### Audit policy tampering
```spl
index=wineventlog EventCode=4719
| where match(SubcategoryGuid, "(?i)(Logon|AccountLogon|ObjectAccess|ProcessCreation)")
| where AuditPolicyChanges="No Auditing"
| table _time, host, SubjectUserName, SubcategoryGuid, AuditPolicyChanges
```

### Hunt Notes
- TH-2026-038 | 2026-04-13 | Marcus Webb | No EDR tamper detected — CrowdStrike RTR policy blocked all service-stop attempts. Recommend: create Splunk ES notable event for ANY service-stopped event on CSFalconService even if the stop failed.
- TH-2025-091 | 2025-11-04 | Alice Chen | wevtutil.exe cl Security observed post-exploitation. Cleared Security log removed 4624 logon evidence. Sysmon log survived (separate channel). Remediation: enable log forwarding to Splunk with < 30s latency to ensure logs captured before clearing.

### False Positives
- CrowdStrike sensor auto-update causes brief service restart — brief stop/start pair within 30s from 10.0.9.10 or svc-cs-update account.
- Sysmon version upgrades from IT Ops scheduled change — brief SysmonDrv stop/start, verify against change ticket.
- No legitimate reason to clear Security or Sysmon logs in production. Zero exceptions.

---

## T1566.001 — Phishing: Spearphishing Attachment

> tactic: Initial Access

Adversaries send targeted emails with malicious attachments (macro-enabled Office docs, LNK files, ISO/IMG containers, PDF with embedded exploit) to gain initial access. Spearphishing attachments are the most common initial access vector across all ransomware and APT campaigns. The attachment typically drops a first-stage loader (CS beacon, Qbot, IcedID) that enables interactive operator access.

### Evidence
- crit | Office application spawning `cmd.exe`, `powershell.exe`, `wscript.exe`, or `mshta.exe` — macro or DDE execution chain (Sysmon EC1).
- crit | `explorer.exe` mounting an ISO or IMG file (Sysmon EC11: TargetFilename matching `*.iso` or `*.img` write to a temp path) followed by LNK execution.
- high | PDF reader spawning a scripting engine or network-enabled binary within 30s of document open.
- high | Outbound HTTPS connection from `WINWORD.EXE` or `EXCEL.EXE` to a newly registered domain (< 30 days) — download-cradle payload.
- info | Email gateway alert (if available) — correlate attachment hash with Splunk ES identity of the recipient to pivot to their endpoint logs.

### Queries

#### Office spawning execution chain (macro delivery)
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)(WINWORD|EXCEL|POWERPNT|MSPUB|MSACCESS|AcroRd32|Acrobat|FoxitReader)\.exe")
| where match(Image, "(?i)(cmd\.exe|powershell|wscript|mshta|cscript|regsvr32|rundll32|certutil|bitsadmin)")
| table _time, host, User, ParentImage, Image, CommandLine
```

#### ISO/LNK container execution (mark-of-the-web bypass)
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)explorer\.exe")
| where match(CommandLine, "(?i)(\.lnk|\.url|wscript|mshta)")
| where match(CurrentDirectory, "(?i)(\\\\AppData|\\\\Downloads|\\\\Temp|[A-Z]:\\\\[A-Z]:\\\\)")
| table _time, host, User, CommandLine, CurrentDirectory
```

#### First outbound connection from Office process
```spl
index=sysmon EventCode=3
| where match(Image, "(?i)(WINWORD|EXCEL|POWERPNT|AcroRd32|Acrobat)\.exe")
| where NOT match(DestinationHostname, "(?i)(microsoft|office|live|onedrive|sharepoint|msocdn)")
| table _time, host, User, Image, DestinationIp, DestinationHostname, DestinationPort
```

### Hunt Notes
- TH-2026-041 | 2026-04-25 | Marcus Webb | Root-cause: spearphish to jsmith@corp.local with Excel attachment enabling macro. Excel→powershell chain confirmed in Sysmon. Email gateway log showed attachment arrived from spoofed vendor domain registered 3 days prior.
- TH-2025-091 | 2025-11-01 | Alice Chen | ISO-in-email bypass — Outlook downloaded ISO, user mounted it, ran contained LNK. No Office macro telemetry fired. ISO mounting generates Sysmon EC11 only — ensure ISO file extension is monitored.

### False Positives
- Email clients launching browser for tracked links — suppress WINWORD→chrome.exe / iexplore.exe chains.
- Adobe Acrobat DC update spawning `AcroRd32.exe` → `msiexec.exe` — validate by parent chain and signed binary hash.
- IT helpdesk running scripts via email-templated instructions — legitimate if source is JUMP-01 and script is signed.

---

## T1055 — Process Injection

> tactic: Defense Evasion / Privilege Escalation

Adversaries inject malicious code into the address space of legitimate running processes to evade process-based defences, elevate privileges, and maintain persistence under a trusted process name. Common techniques: classic DLL injection (CreateRemoteThread), reflective DLL loading, process hollowing (T1055.012), and APC injection (T1055.004). Cobalt Strike beacon routinely injects into `svchost.exe`, `explorer.exe`, and `spoolsv.exe`.

### Evidence
- crit | Sysmon EC8 (CreateRemoteThread) from a non-system process targeting `svchost.exe`, `explorer.exe`, `lsass.exe`, or `spoolsv.exe`.
- crit | Process hollowing indicator: spawned process has `SUSPENDED` thread state immediately followed by `WriteProcessMemory` calls (visible via Sysmon EC10 GrantedAccess `0x1fffff` against a non-LSASS target).
- high | Unsigned or low-entropy PE image mapped into a process that normally only loads signed Microsoft DLLs (memory-only PE — no corresponding file on disk).
- high | `ntdll.dll` or `kernel32.dll` API call sequence: `OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread` from a non-system process.
- info | Sysmon EC7 (ImageLoad) of an unsigned DLL into a high-privilege process — watch for DLLs loaded from `%TEMP%` or `%APPDATA%`.

### Queries

#### CreateRemoteThread into trusted processes
```spl
index=sysmon EventCode=8
| where match(TargetImage, "(?i)(svchost|explorer|spoolsv|lsass|winlogon|csrss)\.exe")
| where NOT match(SourceImage, "(?i)(MsMpEng|CSFalcon|SentinelAgent|CylanceSvc|svchost)\.exe")
| table _time, host, User, SourceImage, TargetImage, StartFunction, StartModule
```

#### Unsigned DLL loaded into high-privilege process
```spl
index=sysmon EventCode=7
| where match(Image, "(?i)(svchost|explorer|spoolsv|lsass)\.exe")
| where Signed="false" OR match(ImageLoaded, "(?i)(\\\\AppData|\\\\Temp|\\\\Users\\\\Public)")
| table _time, host, User, Image, ImageLoaded, Signed, SignatureStatus
```

#### Suspicious cross-process memory access (non-LSASS)
```spl
index=sysmon EventCode=10
| where NOT match(TargetImage, "(?i)lsass\.exe")
| where match(GrantedAccess, "0x1fffff|0x1f3fff|0x40|0x1410")
| where NOT match(SourceImage, "(?i)(MsMpEng|CSFalcon|debugger|drwatson)\.exe")
| table _time, host, SourceImage, TargetImage, GrantedAccess, CallTrace
```

### Hunt Notes
- TH-2026-038 | 2026-04-12 | Marcus Webb | CS beacon injected into `svchost.exe -k netsvcs` on WIN-DC01. Sysmon EC8 from `cmd.exe` to `svchost.exe` — unusual source process. CallTrace showed `UNKNOWN` regions (shellcode stubs not mapped to a module).
- TH-2026-041 | 2026-04-26 | Marcus Webb | Process hollowing of `notepad.exe` — spawned suspended, memory written, then resumed. EC10 access mask `0x1fffff` from `powershell.exe` against notepad. No file on disk for the injected PE.

### False Positives
- CrowdStrike sensor monitors processes with broad access rights — suppress by SourceImage hash of known EDR binaries.
- Windows Defender AMSI scanning opens handles to scripting processes — baseline by MsMpEng.exe source.
- JIT compilers (Java, .NET CLR) perform memory operations that can resemble injection — validate by ImageLoaded module list.

---

## T1021.001 — Remote Services: Remote Desktop Protocol

> tactic: Lateral Movement

Adversaries use RDP to interactively access remote systems using compromised credentials. RDP sessions provide full interactive desktop access and are difficult to distinguish from legitimate admin activity without baselines. Key differentiators: source host anomaly, time-of-day, and cascading RDP sessions (RDP hop through multiple hosts to reach target).

### Evidence
- crit | EventCode 4624 LogonType=10 (RemoteInteractive) from a source IP outside the IT management subnet (10.0.9.0/24) for a privileged account.
- crit | RDP originating from a workstation-class asset (10.0.3.0/24) to a Domain Controller or PAM server — workstations should never RDP to DCs.
- high | Multiple RDP sessions from the same source within 10 minutes to different hosts — interactive lateral spread.
- high | EventCode 4778 (session reconnected) or 4779 (session disconnected) pattern on multiple hosts for the same user account — RDP hopping indicator.
- info | EventCode 1149 in Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational — logs source IP even before full authentication.

### Queries

#### RDP logon from non-management source
```spl
index=wineventlog EventCode=4624 LogonType=10
| where NOT match(IpAddress, "^10\.0\.9\.|^127\.|^::1")
| where NOT match(TargetUserName, "(?i)SYSTEM|\$$|DWM-|UMFD-")
| table _time, host, TargetUserName, IpAddress, WorkstationName
| sort - _time
```

#### Workstation RDP to DC (always suspicious)
```spl
index=wineventlog EventCode=4624 LogonType=10
| where match(IpAddress, "^10\.0\.3\.")
| where match(host, "(?i)WIN-DC")
| table _time, host, TargetUserName, IpAddress, WorkstationName
```

#### RDP lateral spread — session cascade
```spl
index=wineventlog (EventCode=4778 OR EventCode=4779 OR EventCode=4624)
| where LogonType=10 OR EventCode IN (4778, 4779)
| where NOT match(TargetUserName, "(?i)SYSTEM|\$$")
| bucket _time span=10m
| stats dc(host) as hosts, values(host) as host_list by TargetUserName, IpAddress, _time
| where hosts > 2
```

#### RDP source logging (pre-auth, EventCode 1149)
```spl
index=wineventlog source="*TerminalServices*" EventCode=1149
| table _time, host, User, Source_Network_Address
| where NOT match(Source_Network_Address, "^10\.0\.9\.")
```

### Hunt Notes
- TH-2026-041 | 2026-04-26 | Marcus Webb | RDP hop chain: WIN-WS041 → WIN-SRV03 → WIN-DC01. Each hop used a different compromised account. LogonType=10 events on each host. 1149 telemetry showed the originating IP before auth. Chain reconstructed in 20min using timeline correlation.
- TH-2025-091 | 2025-11-03 | Alice Chen | RDP from external IP via exposed VPN concentrator. Attacker used jsmith VPN + RDP to reach JUMP-01 directly. Recommend restricting VPN-sourced RDP to JUMP-01 only via PBR.

### False Positives
- IT helpdesk RDP from JUMP-01 (10.0.9.10) — expected. Suppress by source IP.
- Vendor support sessions (pre-approved) — correlate with CyberArk session ticket and time window.
- IT admin workstations in 10.0.9.0/24 RDPing to servers during maintenance windows — suppress by source subnet and maintenance schedule.

---

## T1021.002 — Remote Services: SMB/Windows Admin Shares

> tactic: Lateral Movement

Adversaries access remote systems via SMB admin shares (C$, ADMIN$, IPC$) to browse file systems, stage tools, and execute code remotely via Service Control Manager. Combined with valid credentials (PtH or stolen), SMB lateral movement is fast and leverages built-in Windows capabilities with minimal noise.

### Evidence
- crit | EventCode 5145 (network share object accessed) with share `ADMIN$` or `C$` by a non-admin, non-automated account — interactive SMB admin share access.
- crit | File written to `\\host\ADMIN$\Temp\` or `\\host\C$\Windows\Temp\` followed within 60s by EventCode 7045 (service installed) on the target host.
- high | EventCode 4776 (NTLM credential validation) on a DC for an account that does not normally use NTLM — PtH precursor.
- high | `net use \\host\C$` or `net use \\host\ADMIN$` via `cmd.exe` from a workstation-class asset — interactive admin share enumeration.
- info | EventCode 5140 (network share accessed) for `IPC$` from a non-server, non-management source — often precedes admin share access.

### Queries

#### Admin share access by non-automated account
```spl
index=wineventlog EventCode=5145
| where match(ShareName, "(?i)(ADMIN\$|C\$|IPC\$)")
| where NOT match(SubjectUserName, "(?i)(SYSTEM|svc-sccm|svc-backup|svc-splunk|\$$)")
| where NOT match(IpAddress, "^10\.0\.(5|9)\.")
| table _time, host, SubjectUserName, ShareName, RelativeTargetName, IpAddress
```

#### Lateral tool staging: write to admin share then service install
```spl
index=wineventlog EventCode=7045
| join host [search index=wineventlog EventCode=5145 ShareName="\\\\*\\\\ADMIN$" Accesses="*WriteData*"
  | eval stg_time=_time | table host, stg_time, SubjectUserName, RelativeTargetName]
| eval delta=_time-stg_time
| where delta >= 0 AND delta < 120
| table _time, host, SubjectUserName, RelativeTargetName, ServiceName, delta
```

#### Net use admin share from workstation
```spl
index=sysmon EventCode=1 Image="*net.exe"
| where match(CommandLine, "(?i)net.+(use|view).+\\\\\\\\")
| where match(CommandLine, "(?i)(ADMIN\$|C\$|IPC\$)")
| table _time, host, User, CommandLine
```

### Hunt Notes
- TH-2026-038 | 2026-04-12 | Marcus Webb | svc-backup hash used via PtH to write `svchost.exe` (renamed netcat) to ADMIN$ on 14 Server Farm hosts. EventCode 5145 showed write events; 7045 showed service install within 45s on each. Service name: `WindowsUpdater`.
- TH-2026-041 | 2026-04-27 | Marcus Webb | jsmith NTLM hash used for C$ browsing to enumerate host file systems before lateral movement tool staging.

### False Positives
- SCCM/Intune deployment writes to ADMIN$ from svc-sccm (10.0.5.20) — suppress by source account and IP.
- Backup agents write to ADMIN$ as part of VSS — suppress svc-backup during backup window 01:00–04:00.
- IT Ops manual access from JUMP-01 (10.0.9.10) using adm-itops — expected; correlate with CyberArk ticket.

---

## T1543.003 — Create or Modify System Process: Windows Service

> tactic: Persistence / Privilege Escalation

Adversaries create or modify Windows services to execute malicious code with SYSTEM privileges and achieve boot-persistence. Services run as SYSTEM by default, providing the highest level of local privilege. Common methods: `sc.exe create`, `New-Service` PowerShell cmdlet, or direct SCM API calls (bypasses sc.exe telemetry).

### Evidence
- crit | EventCode 7045 (new service installed) with a binary path in `C:\Windows\Temp\`, `C:\Users\`, or `C:\ProgramData\` — legitimate services rarely install to user-writable locations.
- crit | Service created with `binPath` pointing to `cmd.exe /c`, `powershell.exe -enc`, or a LOLBin — command execution masquerading as a service.
- high | `sc.exe create` or `sc.exe config` from a non-admin account or invoked by a scripting engine (PowerShell, wscript parent).
- high | EventCode 7036 (service state change) for a newly installed service that transitions to Running within 5s of installation — immediate execution after creation.
- info | Service binary path matches known malware patterns: high-entropy filename, no version info, missing authenticode signature.

### Queries

#### New service with suspicious binary path
```spl
index=wineventlog EventCode=7045
| where match(ServiceFileName, "(?i)(\\\\Temp\\\\|\\\\Users\\\\|\\\\ProgramData\\\\|cmd\.exe|powershell|wscript|mshta)")
| where NOT match(ServiceFileName, "(?i)(\\\\Windows\\\\System32\\\\|\\\\Program Files\\\\)")
| table _time, host, ServiceName, ServiceFileName, ServiceType, ServiceAccount
```

#### sc.exe create from scripting parent
```spl
index=sysmon EventCode=1 Image="*sc.exe"
| where match(CommandLine, "(?i)(create|config|binpath)")
| where match(ParentImage, "(?i)(powershell|cmd|wscript|mshta|cscript)")
| table _time, host, User, ParentImage, CommandLine
```

#### Service installed and started within 10 seconds
```spl
index=wineventlog (EventCode=7045 OR EventCode=7036)
| eval install_time=if(EventCode=7045, _time, null()), start_time=if(EventCode=7036 AND match(Message,"running"), _time, null())
| stats min(install_time) as installed, min(start_time) as started by host, ServiceName
| eval delta=started-installed
| where delta >= 0 AND delta < 10
| table host, ServiceName, installed, started, delta
```

### Hunt Notes
- TH-2026-038 | 2026-04-12 | Marcus Webb | Malicious service `WindowsUpdater` installed on 14 hosts via SC Manager API (no sc.exe — bypassed EC1). Detected via EC7045 only. Binary path: `C:\Windows\Temp\svchost.exe` (renamed netcat). No authenticode signature.
- TH-2025-091 | 2025-11-04 | Alice Chen | Attacker used `sc create` from PowerShell to install a service pointing to a PS1 script in C:\ProgramData\. EventCode 7045 captured. Service name was randomly generated 8-char string.

### False Positives
- SCCM software deployment (ccmexec.exe) creates services during application installation — validate by parent process and svc-sccm account.
- CrowdStrike sensor installation creates CSFalconService — suppress by known binary hash and signing cert.
- Legitimate software vendors (e.g., Splunk, Sysmon) install services during initial setup — validate by signed binary and expected installer path.

---

## T1082 — System Information Discovery

> tactic: Discovery

Adversaries enumerate the target system to understand the environment: OS version, hardware, domain membership, security software, and network configuration. This reconnaissance typically occurs in the first 5–15 minutes after initial access and before lateral movement. Common tools: `systeminfo.exe`, `ipconfig /all`, `net` commands, WMI queries, and PowerShell `Get-WmiObject`.

### Evidence
- high | Burst of discovery commands within a short window from an interactive user session: `systeminfo`, `whoami`, `net user /domain`, `net group "Domain Admins"`, `ipconfig /all`, `arp -a` (5+ within 2 minutes).
- high | `systeminfo.exe` or `wmic computersystem get` executed from a scripting parent (PowerShell, wscript) — automated reconnaissance.
- high | `nltest /domain_trusts`, `nltest /dclist:` — domain trust enumeration, common in pre-lateral movement.
- info | `query user`, `tasklist /v`, `sc queryex type= service state= all` — session and service enumeration post-access.

### Queries

#### Discovery command burst from interactive session
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(systeminfo|whoami|ipconfig|net\.exe|nltest|arp\.exe|hostname|netstat)\.exe")
| where NOT match(User, "(?i)SYSTEM|\$$")
| bucket _time span=2m
| stats count, values(Image) as tools, values(CommandLine) as commands by host, User, _time
| where count >= 3
| sort - count
```

#### Domain enumeration commands
```spl
index=sysmon EventCode=1 Image="*net.exe"
| where match(CommandLine, "(?i)(user /domain|group.+(Domain Admins|Enterprise|Schema)|localgroup administrators|accounts /domain)")
| table _time, host, User, CommandLine
```

#### Trust and DC enumeration
```spl
index=sysmon EventCode=1 Image="*nltest.exe"
| where match(CommandLine, "(?i)(domain_trusts|dclist|dsgetdc|parentdomain)")
| table _time, host, User, CommandLine, ParentImage
```

### Hunt Notes
- TH-2026-041 | 2026-04-26 | Marcus Webb | Classic post-exploitation recon pattern within 3 minutes of initial access on WIN-WS041: whoami → systeminfo → ipconfig /all → net group "Domain Admins" /domain → nltest /domain_trusts. All from same PowerShell session. Confirmed via ScriptBlock log (EC4104).
- TH-2026-038 | 2026-04-11 | Marcus Webb | Discovery commands issued via WMI remote execution (WmiPrvSE parent) — no interactive session on target. Output captured via named pipe back to attacker host.

### False Positives
- SCCM hardware inventory (svc-sccm) runs `systeminfo` and WMI queries on all hosts — exclude by source account and parent ccmexec.exe.
- Vulnerability scanners (Tenable/Nessus) run discovery commands — suppress by source IP of scanner appliance.
- New employee workstation provisioning scripts run domain group queries — suppress by svc-provisioning account during provisioning window.

---

## T1005 — Data from Local System

> tactic: Collection

Adversaries collect data from local file systems before exfiltration. In enterprise intrusions, targets include credentials files, configuration files, browser data, documents matching keyword patterns, and database content. Common tools: `robocopy`, PowerShell `Get-ChildItem`, `findstr`, custom staging scripts.

### Evidence
- high | Bulk file read operations from `C:\Users\` directories by a process other than the logged-in user's own session — cross-account file access.
- high | `robocopy` or `xcopy` with recursive flags targeting `Documents\`, `Desktop\`, or network share paths from an automated/scripting context.
- high | PowerShell `Get-ChildItem -Recurse` with `-Filter` for `.doc`, `.docx`, `.xlsx`, `.pdf`, `.kdb`, `.pfx`, `.key` — credential and document collection.
- high | Access to `C:\Users\*\AppData\Roaming\` directories by a non-owner process — browser credential stores, password manager databases.
- info | Staging to a single compressed archive (`.zip`, `.7z`, `.rar`) in a temp path before exfil — Sysmon EC11 on archive creation followed by network connection (EC3).

### Queries

#### Bulk document collection via PowerShell
```spl
index=sysmon EventCode=1 (Image="*powershell.exe" OR Image="*pwsh.exe")
| where match(CommandLine, "(?i)(Get-ChildItem|gci|dir).+(-recurse|-r).+\.(doc|xls|pdf|txt|pfx|kdb|key|config|xml)")
| table _time, host, User, CommandLine
```

#### File staging to compressed archive
```spl
index=sysmon EventCode=11
| where match(TargetFilename, "(?i)(\.zip|\.7z|\.rar|\.tar\.gz)$")
| where NOT match(TargetFilename, "(?i)(\\\\Program Files|\\\\Windows\\\\|\.nuget|update)")
| where NOT match(Image, "(?i)(7z|winrar|winzip|backup|sccm|teamsupdate)")
| table _time, host, User, Image, TargetFilename
```

#### Robocopy/xcopy recursive staging
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(robocopy|xcopy|copy)\.exe")
| where match(CommandLine, "(?i)(/s |/e |/mir|/copyall).+(\\\\Users|\\\\Documents|\\\\Desktop)")
| where NOT match(User, "(?i)SYSTEM|svc-backup")
| table _time, host, User, CommandLine
```

### Hunt Notes
- TH-2026-041 | 2026-04-27 | Marcus Webb | PS script collected all .docx and .pdf from C:\Users\ on WIN-WS041 and 3 additional hosts via PtH. Archives staged to C:\Windows\Temp\out.7z before exfil via HTTPS. Sysmon EC11 on 7z creation preceded EC3 outbound to C2.
- TH-2026-038 | 2026-04-13 | Marcus Webb | Database credentials harvested from web app config files on SQL-DB01. `findstr /S /I password *.config` run from WMI. No bulk collection — targeted credential hunting.

### False Positives
- DLP solutions scanning file content — large-scale file read operations from DLP agent service account are expected.
- Backup agents (svc-backup via Veeam) reading all files recursively — suppress by source account during backup window.
- User-initiated bulk copy for legitimate work — context matters; correlate with HR/IT service desk ticket if volume is high.

---

## T1048 — Exfiltration Over Alternative Protocol

> tactic: Exfiltration

Adversaries exfiltrate collected data using protocols not blocked by egress filtering — DNS tunnelling (T1048.001), ICMP tunnelling, FTP, SMB to external IPs, or HTTPS to an IP address with no SNI. Alternative-protocol exfiltration evades DLP tools tuned only to standard HTTP/S traffic.

### Evidence
- crit | DNS TXT or NULL record responses carrying data (record length > 200 bytes) — DNS exfiltration via TXT record responses.
- crit | Outbound ICMP echo requests with payload size > 1024 bytes or high-entropy payload data — ICMP tunnel exfiltration.
- high | Outbound SMB (TCP 445) to an external (non-RFC-1918) IP — lateral movement tool does not normally use external SMB.
- high | Outbound FTP (TCP 21) or SFTP (TCP 22) from a workstation-class asset to a non-approved external IP — no business justification.
- high | Large outbound HTTPS transfer (> 10 MB) to an IP address with no SNI, or SNI does not match certificate Subject — encrypted tunnel bypassing SSL inspection.

### Queries

#### DNS TXT exfiltration — large responses
```spl
index=dns record_type=TXT
| eval response_len=len(answer)
| where response_len > 200
| where NOT match(query, "(?i)(microsoft|google|amazon|spf|dkim|dmarc|_domainkey)")
| stats count, max(response_len) as max_len, values(query) as queries by src_ip
| where count > 3
```

#### ICMP tunnel — oversized payload
```spl
index=network protocol=ICMP
| where bytes > 1024
| where NOT match(dest_ip, "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.")
| stats sum(bytes) as total_bytes, count by src_ip, dest_ip
| where total_bytes > 102400
| sort - total_bytes
```

#### Outbound SMB to external IP
```spl
index=firewall dest_port=445 action=allow
| where NOT match(dest_ip, "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.")
| stats count, sum(bytes_out) as total_bytes by src_ip, dest_ip
| sort - total_bytes
```

#### Large HTTPS transfer to bare IP (no SNI)
```spl
index=proxy OR index=ssl
| where NOT match(dest_host, "[a-zA-Z]")
| eval dest_is_ip=if(match(dest_host, "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"), 1, 0)
| where dest_is_ip=1 AND bytes_out > 10485760
| table _time, src_ip, dest_host, bytes_out, user_agent
```

### Hunt Notes
- TH-2026-041 | 2026-04-27 | Marcus Webb | DNS TXT exfiltration from WIN-WS041 to `*.update-cdn[.]net` — TXT records returned base64-encoded chunks. Identified via DNS log: record_type=TXT, avg answer length 312 bytes. 14 MB total exfil estimated over 4h. Blocked at perimeter; data already gone for ~3h window.
- TH-2026-038 | 2026-04-13 | Marcus Webb | No exfil observed — incident interdicted before staging complete. Review proxy logs for large HTTPS to IP addresses (no SNI) as standing hunt.

### False Positives
- CDN providers with IP-based HTTPS (e.g., Cloudflare Spectrum) — validate destination IP ownership before escalating.
- VPN software using ICMP keepalives — suppress by known VPN client binary (Cisco AnyConnect, Palo Alto GlobalProtect).
- Backup software using FTP/SFTP to approved DR site — suppress by destination IP of DR site (10.10.0.0/16).

---

## T1486 — Data Encrypted for Impact

> tactic: Impact

Adversaries encrypt files on target systems and demand ransom for the decryption key. Modern ransomware (LockBit 3.0, BlackCat/ALPHV, Akira) performs targeted deployment — files are not encrypted until the attacker has mapped the environment, exfiltrated data, and disabled backups. Detection at this stage represents the final opportunity before significant business impact.

### Evidence
- crit | Rapid, sequential file modifications across multiple directories with simultaneous creation of ransom note files (`README.txt`, `*.HOW_TO_DECRYPT`, `RECOVER-FILES.html`) — active encryption underway.
- crit | Volume of file rename events (Sysmon EC11) exceeding 1,000 per minute with consistent extension appended (e.g., `.locked`, `.akira`, `.alphv`) — ransomware file chaining.
- crit | Previous indicator T1490 (shadow deletion) occurred on same host within the last 10 minutes — encryption is imminent.
- high | Process with high I/O rate creating files with changed extensions in rapid sequence — no single binary involved, look for child of batch or PS.
- info | Windows VSS service error events appearing after shadow deletion — OS unable to create recovery point.

### Queries

#### Ransom note creation — immediate escalation
```spl
index=sysmon EventCode=11
| where match(TargetFilename, "(?i)(README|HOW_TO|DECRYPT|RECOVER|RESTORE|ransom|HELP_RESTORE)(.*)\.(txt|html|hta|rtf)$")
| table _time, host, User, Image, TargetFilename
| sort - _time
```

#### Rapid file rename/encrypt pattern
```spl
index=sysmon EventCode=11
| where NOT match(TargetFilename, "(?i)(\.tmp|\.log|thumbs\.db|desktop\.ini)")
| bucket _time span=1m
| stats count, dc(TargetFilename) as unique_files, values(Image) as processes by host, _time
| where count > 500
| sort - count
```

#### Extension change flood (ransomware sweep)
```spl
index=sysmon EventCode=11
| eval ext=replace(TargetFilename, ".*\.", ".")
| where NOT match(ext, "(?i)\.(tmp|log|db|ini|bak|lnk|pf|etl)$")
| bucket _time span=1m
| stats dc(ext) as ext_variety, count by host, Image, _time
| where count > 200 AND ext_variety < 5
| sort - count
```

### Hunt Notes
- TH-2026-038 | 2026-04-13 | Marcus Webb | Ransomware deployment interdicted before encryption stage. Shadow deletion command found but not executed. IR action: network isolation of WIN-WS041 and 3 adjacent hosts. If encryption had started, estimated impact: ~8,000 files across Server Farm before isolation.
- TH-2025-091 | 2025-11-06 | Alice Chen | Post-incident note: encrypt phase was only 7 minutes total. From first ransom note creation to complete file system encryption was 7m 22s. Current Splunk ES polling interval is 5m — will miss the window. Recommend real-time streaming alert on ransom note creation.

### False Positives
- Encryption software (VeraCrypt, BitLocker provisioning) creates files with changed extensions during setup — validate by known-good signed binary hash and IT change ticket.
- Backup software creating compressed/encrypted archive copies — suppress by svc-backup account and backup window.
- Zero false positives expected for ransom note creation pattern — no legitimate process creates `HOW_TO_DECRYPT.txt` files.

---

## T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay

> tactic: Credential Access

Adversaries use Responder or Inveigh to poison LLMNR (UDP 5355) and NetBIOS-NS (UDP 137) responses, capturing NTLMv2 challenge/response hashes from any host attempting to resolve a non-existent name. The hash is either cracked offline or relayed immediately via ntlmrelayx to a vulnerable host. This attack requires no privileges and works from any network segment where LLMNR is not disabled.

### Evidence
- crit | NTLMv2 authentication (EventCode 4776) from a host to an IP address that is not a Domain Controller or legitimate server — Responder-on-the-wire.
- crit | Sysmon EC3: outbound NetBIOS-NS (UDP 137) or LLMNR (UDP 5355) query answered by an unexpected IP (same subnet, non-DC) — poisoner responding.
- high | Multiple `NTLMSSP_AUTH` captures in network traffic from different source hosts to the same rogue IP within a short window — Responder listener.
- high | New SMB connection from a DC or high-value server to a workstation-class IP — potential SMB relay success.
- info | EventCode 4624 LogonType=3 on a server where no one has legitimate access in that window — relay authentication landing.

### Queries

#### NTLM auth to unexpected (non-DC, non-server) destination
```spl
index=wineventlog EventCode=4776
| where NOT match(Workstation, "(?i)WIN-DC|WIN-SRV")
| stats count, values(TargetUserName) as accounts by Workstation, Status
| where count > 5
| sort - count
```

#### Outbound NTLM to non-DC from workstation
```spl
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
| where match(IpAddress, "^10\.0\.3\.")
| where NOT match(host, "(?i)WIN-DC|WIN-SRV")
| stats count, values(TargetUserName) as users by IpAddress, host
| sort - count
```

#### Anomalous SMB from server to workstation
```spl
index=firewall dest_port=445 action=allow
| where match(src_ip, "^10\.0\.(1|2)\.")
| where match(dest_ip, "^10\.0\.3\.")
| stats count, values(dest_ip) as targets by src_ip
| where count > 3
| sort - count
```

#### LLMNR/NBT-NS traffic volume spike
```spl
index=network (dest_port=5355 OR dest_port=137) protocol IN (UDP)
| bucket _time span=5m
| stats count, dc(src_ip) as sources by dest_ip, _time
| where count > 50 AND sources > 5
| sort - count
```

### Hunt Notes
- TH-2026-041 | 2026-04-25 | Marcus Webb | Responder running on WIN-WS041 for ~40 minutes before detection. 23 NTLMv2 hashes captured (various user accounts). svc-backup hash captured and cracked (8-char password, 4h crack time). LLMNR not disabled by GPO in Corp-Workstations OU — remediation ticket raised (CORP-3892).
- TH-2025-091 | 2025-11-02 | Alice Chen | SMB relay via ntlmrelayx from compromised workstation to SQL-DB01 — no signing on SQL server. Lateral access established without cracking. SQL server now requires SMB signing (enforced via GPO CORP-SEG-002).

### False Positives
- Legitimate LLMNR queries for mistyped hostnames are expected — Responder is distinguished by the SAME IP answering multiple queries from different hosts.
- Network scanning tools (Nmap, Nessus) may probe UDP 137 — suppress by known scanner IP.
- SMB connections from DCs to workstations for GPO processing and SYSVOL access — validate by destination port 445 with CIFS authentication context (EventCode 4624 NtLmSsp vs Kerberos).
