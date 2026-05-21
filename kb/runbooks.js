// ════════════════════════════════════════════════════════════════════════════
// TTP RUNBOOKS  —  kb/runbooks.js
// ════════════════════════════════════════════════════════════════════════════
// One entry per MITRE ATT&CK technique. Agents load these at hunt time via
// get_runbook(ttp_id). Also rendered in Knowledge Base → TTP Runbooks tab.
//
// To add a new runbook, copy the template below and fill it in:
//
// 'T1234.001': {
//   name: 'Technique Name',
//   tactic: 'Tactic Name',         // or 'Tactic A / Tactic B' for multi-tactic
//   summary: 'One-paragraph description of the technique and adversary use.',
//   evidence: [
//     { sev:'crit', text:'What a critical indicator looks like, with <code>code</code> if needed.' },
//     { sev:'high', text:'High-severity indicator.' },
//     { sev:'info', text:'Hunting tip or context note.' },
//   ],
//   queries: [
//     { label:'Query label shown in UI', spl:`index=... | ...` },
//   ],
//   huntNotes: [
//     { hunt:'TH-2026-XXX', date:'YYYY-MM-DD', analyst:'Name', text:'Free-text note from a prior hunt.' },
//   ],
//   fps: [
//     'Known false positive pattern and how to exclude it.',
//   ],
// },
// ════════════════════════════════════════════════════════════════════════════

const runbookData = {
  'T1003.001': {
    name: 'OS Credential Dumping: LSASS Memory',
    tactic: 'Credential Access',
    summary: 'Adversaries access the LSASS process to extract plaintext passwords, hashes, and Kerberos tickets. Common tools include Mimikatz, ProcDump, and Task Manager.',
    evidence: [
      { sev:'crit', text:'Process handle to <code>lsass.exe</code> with access mask <code>0x1fffff</code> (PROCESS_ALL_ACCESS) from a non-AV/EDR source image.' },
      { sev:'crit', text:'<code>sekurlsa::logonpasswords</code> or <code>sekurlsa::wdigest</code> in command-line arguments — direct Mimikatz invocation.' },
      { sev:'high', text:'<code>MiniDumpWriteDump</code> API calls targeting <code>lsass.exe</code> PID from <code>procdump.exe</code>, <code>rundll32.exe comsvcs.dll MiniDump</code>, or custom loaders.' },
      { sev:'high', text:'Driver load of <code>mimidrv.sys</code> or unsigned kernel driver interacting with LSASS.' },
      { sev:'info', text:'Check Sysmon Event ID 10 (ProcessAccess) for <code>TargetImage = lsass.exe</code> with <code>GrantedAccess != 0x1410</code> (standard AV pattern).' },
    ],
    queries: [
      { label:'Sysmon Event 10 — suspicious LSASS handle', spl:`index=sysmon EventCode=10 TargetImage="*lsass.exe"
  NOT SourceImage IN ("*\\\\MsMpEng.exe","*\\\\CylanceSvc.exe","*\\\\SentinelAgent.exe")
| eval suspicious=if(match(GrantedAccess,"0x1fffff|0x1410ff|0x143a"),1,0)
| where suspicious=1
| stats count by SourceImage, GrantedAccess, host, _time
| sort -count` },
      { label:'comsvcs.dll MiniDump LOLBin', spl:`index=windows EventCode=4688
  CommandLine="*comsvcs*" CommandLine="*MiniDump*"
| table _time, host, user, CommandLine` },
    ],
    huntNotes: [
      { hunt:'TH-2026-038', date:'2026-04-12', analyst:'Marcus Webb', text:'Confirmed rundll32.exe comsvcs.dll MiniDump on WIN-DC01. Dump written to C:\\Windows\\Temp\\lsass.dmp then exfil via SMB. Added hash of dump file to threat intel.' },
      { hunt:'TH-2025-091', date:'2025-11-03', analyst:'Alice Chen', text:'ProcDump blocked by EDR but attacker pivoted to Task Manager manual dump. Recommend monitoring \\AppData\\Local\\Temp for .dmp files >10MB.' },
    ],
    fps: [
      'Windows Defender and CrowdStrike routinely open LSASS with 0x1410 access — filter by SourceImage.',
      'Some vulnerability scanners and backup agents (Veeam, BackupExec) legitimately open LSASS. Baseline and exclude by hash.',
    ],
  },

  'T1078.002': {
    name: 'Valid Accounts: Domain Accounts',
    tactic: 'Initial Access / Persistence / Privilege Escalation',
    summary: 'Adversaries use compromised domain credentials to authenticate to systems and services, blending with legitimate user activity. Volt Typhoon heavily favours this technique to maintain persistence without dropping malware.',
    evidence: [
      { sev:'crit', text:'Domain account authenticating from an unusual source host — IP not in user\'s normal subnet or geolocation anomaly.' },
      { sev:'crit', text:'Off-hours logon (Event 4624/4769) from a service account that normally only runs scheduled tasks.' },
      { sev:'high', text:'Single account performing lateral movement to ≥5 hosts within a 30-minute window (use 4769 TGS requests as proxy).' },
      { sev:'info', text:'Cross-reference with VPN/proxy logs — Volt Typhoon frequently accesses domain accounts from SOHO-router-proxied IPs (AS numbers: small ISPs, residential blocks).' },
    ],
    queries: [
      { label:'Off-hours domain logon anomaly', spl:`index=security EventCode=4624 Logon_Type=3
| eval hour=tonumber(strftime(_time,"%H")), dow=strftime(_time,"%A")
| where (hour < 6 OR hour > 21) AND dow!="Saturday" AND dow!="Sunday"
| stats dc(host) as hosts_touched, values(host) as hosts by user, src_ip
| where hosts_touched > 2
| sort -hosts_touched` },
      { label:'Single account TGS-REQ spike (lateral movement)', spl:`index=windows EventCode=4769 Ticket_Encryption_Type=0x17
  NOT Service_Name IN ("krbtgt","*$")
| bucket _time span=30m
| stats dc(Service_Name) as spns, values(Service_Name) as services by Account_Name, Client_Address, _time
| where spns > 8
| sort -spns` },
    ],
    huntNotes: [
      { hunt:'TH-2026-038', date:'2026-04-11', analyst:'Marcus Webb', text:'jsmith account used from 3 different source IPs overnight. One IP resolved to a compromised SOHO router in AS63949. Single-hop threshold set at 14 hosts before escalation.' },
    ],
    fps: [
      'IT admin accounts legitimately log in after hours during maintenance windows — maintain a scheduled-maintenance allowlist.',
      'Service accounts running scripts will show bulk TGS requests; exclude by SPN pattern (SCCM, BackupExec, SQL).',
    ],
  },

  'T1570': {
    name: 'Lateral Tool Transfer',
    tactic: 'Lateral Movement',
    summary: 'Adversaries transfer tools or malware to remote systems via SMB, WMI, RDP clipboard, or LOLBins. Often follows valid-account abuse to stage additional payloads.',
    evidence: [
      { sev:'crit', text:'Executable written to <code>\\\\host\\ADMIN$\\Temp\\</code> or <code>\\\\host\\C$\\Windows\\Temp\\</code> by a user account (not a known deployment tool).' },
      { sev:'high', text:'SMB file write of <code>.exe</code>, <code>.dll</code>, or <code>.ps1</code> followed within 60s by a Service Control Manager event (Event 7045) on the target host.' },
      { sev:'info', text:'Correlate Sysmon Event 11 (FileCreate) on target with Sysmon Event 3 (NetworkConnect) on source — timestamp delta <5s is a strong indicator.' },
    ],
    queries: [
      { label:'SMB write to admin share → service install', spl:`index=windows EventCode=7045
| eval install_time=_time
| join host [search index=security EventCode=5145 Share_Name="\\\\*\\\\ADMIN$" Object_Type=File Accesses="WriteData*"
  | eval write_time=_time | table host, write_time, Relative_Target_Name, Account_Name]
| eval delta=install_time-write_time
| where delta>=0 AND delta<120
| table _time, host, Account_Name, Relative_Target_Name, Service_Name, delta` },
    ],
    huntNotes: [
      { hunt:'TH-2026-038', date:'2026-04-12', analyst:'Marcus Webb', text:'Tool staged to ADMIN$ share on 14 hosts. File was a renamed copy of netcat (nc64.exe → svchost.exe). Hash: d41d8cd98f00b204e9800998ecf8427e.' },
    ],
    fps: [
      'SCCM and Intune push executables to admin shares constantly — exclude by source account (svc-sccm, svc-intune).',
      'Backup agents write to ADMIN$ as part of VSS operations — correlate with backup schedule.',
    ],
  },

  'T1053.005': {
    name: 'Scheduled Task/Job: Scheduled Task',
    tactic: 'Execution / Persistence / Privilege Escalation',
    summary: 'Adversaries create scheduled tasks to execute malicious code repeatedly or at specific times. A common persistence mechanism on Windows requiring only user-level privilege with the right API calls.',
    evidence: [
      { sev:'crit', text:'Scheduled task created by <code>schtasks.exe /create</code> running from a non-standard parent (e.g. <code>powershell.exe</code>, <code>wscript.exe</code>, <code>mshta.exe</code>).' },
      { sev:'high', text:'Task XML written directly to <code>C:\\Windows\\System32\\Tasks\\</code> via a file-write API (bypasses schtasks.exe logging).' },
      { sev:'info', text:'Event 4698 (task created) + 4702 (task updated) in the Security log. Correlate with the task\'s Action element — look for encoded PowerShell or paths outside <code>C:\\Windows\\System32</code>.' },
    ],
    queries: [
      { label:'Suspicious scheduled task creation', spl:`index=windows EventCode=4698
| spath input=Task_Content output=task_action path=Task.Actions.Exec.Command
| where match(task_action,"powershell|cmd|wscript|mshta|regsvr32|rundll32")
   OR match(task_action,"\\\\AppData|\\\\Temp|\\\\Users\\\\Public")
| table _time, host, user, Task_Name, task_action` },
    ],
    huntNotes: [
      { hunt:'TH-2025-091', date:'2025-11-04', analyst:'Alice Chen', text:'Task created under SYSTEM context using COM object ITaskService — bypassed schtasks.exe. No 4698 event fired; detected via Sysmon file-create in Tasks directory.' },
    ],
    fps: [
      'SCCM ConfigMgr creates tasks named ConfigMgr_* — exclude by Task_Name pattern.',
      'Software update agents (Chrome, Teams, Adobe) create tasks in user AppData — baseline by publisher signature.',
    ],
  },

  'T1003': {
    name: 'OS Credential Dumping',
    tactic: 'Credential Access',
    summary: 'Parent technique covering all credential dumping sub-techniques. See T1003.001 (LSASS) for the most common variant.',
    evidence: [
      { sev:'info', text:'Start with T1003.001 (LSASS) for Windows environments. Also check T1003.002 (SAM), T1003.003 (NTDS) for domain controller targeting.' },
    ],
    queries: [],
    huntNotes: [],
    fps: [],
  },

  // ── Add new runbooks below this line ──────────────────────────────────────
};
