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
