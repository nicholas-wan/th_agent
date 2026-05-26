/* ── check.js ────────────────────────────────────────────────────────────
   Check stage — rule filter, query iterations, RAA results, velocity data,
   finding comments. Loaded after pipeline.js, before keep.js.
   ──────────────────────────────────────────────────────────────────────── */
// ── Coverage rule filter ──
function filterRules(hunt, btn) {
  // Reset all filter buttons
  document.querySelectorAll('.rule-filter-btn').forEach(b => {
    b.classList.remove('active');
    b.style.background = '';
    b.style.borderColor = '';
    b.style.color = '';
  });
  // Highlight active button
  btn.classList.add('active');
  btn.style.background = 'rgba(59,130,246,.12)';
  btn.style.borderColor = 'var(--blue)';
  btn.style.color = 'var(--blue)';
  // Show/hide rule rows
  document.querySelectorAll('.rule-row').forEach(row => {
    row.style.display = (hunt === 'all' || row.dataset.hunt === hunt) ? '' : 'none';
  });
}

// ── Active hunt tracker (set by resetCheckForHunt in app.js) ──
let _activeHuntId = '041';

// ── Query iteration chains — per hypothesis (Detection Logic Agent reasoning) ──
// failMode: 'too-many' = alert flood, 'no-results' = zero hits (field/index issue), undefined = pass/warn
const queryIterations = {
  h01: [
    { ttp:'T1570', name:'Lateral Tool Transfer — PsExec file drop via ADMIN$', finalBadge:'PASS',
      iters:[
        { num:1, badge:'FAIL', failMode:'too-many', metric:'Too many — 2,341 alerts',
          spl:`index=windows EventCode=5145 Share_Name="*ADMIN$*"
| stats count by host, src_ip, Account`,
          reason:'Query too broad — SCCM, Ansible, and Veeam all write to ADMIN$ constantly during patch windows. 2,341 events with no way to distinguish PsExec from legitimate IT traffic.',
          action:'Scope to known-bad source IPs; require RelativeTargetName match on PsExec service file patterns' },
        { num:2, badge:'WARN', failMode:'too-many', metric:'Still too many — 134 alerts',
          spl:`index=windows EventCode=5145 Share_Name="*ADMIN$*"
  RelativeTargetName="*PSEXESVC*" OR RelativeTargetName="*.exe"
| where src_ip != "10.0.5.20" AND src_ip != "10.0.5.21"
| stats count by host, src_ip, Account`,
          reason:'Better, but still too noisy — legitimate admin tools also drop service executables to ADMIN$. File drop alone is not enough without confirming the executable actually ran.',
          action:'Join with EventCode=7045 (service install) to confirm execution followed the file drop' },
        { num:3, badge:'PASS', metric:'14 alerts · confirmed',
          spl:`index=windows EventCode=5145 Share_Name="*ADMIN$*"
  (RelativeTargetName="*PSEXESVC*" OR RelativeTargetName="*.exe")
| where src_ip != "10.0.5.20" AND src_ip != "10.0.5.21"
| join type=inner host [
    index=windows EventCode=7045
    | rename host as host, ServiceFileName as svc_file ]
| stats count by host, src_ip, Account, svc_file`,
          reason:'14 hits — file drop correlated with service install on same host. All from non-IT source addresses. Analyst-reviewed and confirmed suspicious.' }
      ]
    },
    { ttp:'T1078.002', name:'Domain Account — credential reuse across multiple hosts', finalBadge:'WARN',
      iters:[
        { num:1, badge:'FAIL', failMode:'too-many', metric:'Too many — 623 alerts',
          spl:`index=wineventlog EventCode=4624 Logon_Type=3 Account_Name!="*$"
| stats dc(host) as host_count, values(src_ip) as sources by Account_Name
| where host_count > 3`,
          reason:'Query too broad — svc-sccm and svc-veeam touch dozens of hosts every maintenance window. Service account traffic swamps the signal.',
          action:'Exclude service account prefixes; tighten to a 15-minute burst window to isolate rapid multi-host pivots' },
        { num:2, badge:'WARN', metric:'31 alerts · 1 advisory',
          spl:`index=wineventlog EventCode=4624 Logon_Type=3 Account_Name!="*$"
| where NOT match(Account_Name,"^svc-|^krbtgt|^MSOL_")
| bucket _time span=15m
| stats dc(host) as host_count, values(src_ip) as sources by Account_Name, _time
| where host_count > 4`,
          reason:'Volume manageable — jsmith confirmed lateral movement to 6 hosts in 3 min. ~4% remaining noise from help-desk accessing user workstations. Advisory: burst window may need per-shift tuning.' }
      ]
    }
  ],
  h02: [
    { ttp:'T1003.001', name:'LSASS Memory — full-access handle dump (SK-029)', finalBadge:'PASS',
      iters:[
        { num:1, badge:'FAIL', failMode:'no-results', metric:'No results — field not mapped',
          spl:`index=crowdstrike event_simpleName=ProcessRollup2
  TargetFileName="*lsass.exe*"
| stats count by ComputerName, UserName, CommandLine, process_handle_flags`,
          reason:'Zero results — process_handle_flags is not available in the CIM-normalised data model. Field silently dropped at the Splunk CIM mapping layer. Query returns nothing.',
          action:'Switch to raw Sysmon EventCode=10; use GrantedAccess field as the access-mask proxy' },
        { num:2, badge:'FAIL', failMode:'too-many', metric:'Too many — 189 alerts',
          spl:`index=sysmon EventCode=10 TargetImage="*lsass.exe*"
| stats count by SourceImage, GrantedAccess, host`,
          reason:'Query too broad — svchost.exe, MsMpEng.exe (Defender), CrowdStrike, and every other security tool on the box legitimately opens LSASS handles. 189 events, nearly all benign.',
          action:'Apply SK-029 pattern: filter on GrantedAccess=0x1fffff (full access mask); exclude known EDR/AV process names' },
        { num:3, badge:'PASS', metric:'5 alerts · confirmed',
          spl:`index=sysmon EventCode=10 TargetImage="*lsass.exe*"
  GrantedAccess="0x1fffff"
| where NOT match(SourceImage,"(?i)MsMpEng|CrowdStrike|SentinelOne|velociraptor")
| stats count by SourceImage, GrantedAccess, host, user`,
          reason:'5 hits — rundll32.exe requesting full LSASS access (0x1fffff). SK-029 NtDuplicateObject pattern confirmed. No legitimate process needs this mask.' }
      ]
    },
    { ttp:'T1558.003', name:'Kerberoasting — RC4 TGS requests (SK-038 exclusions)', finalBadge:'PASS',
      iters:[
        { num:1, badge:'FAIL', failMode:'too-many', metric:'Too many — 341 alerts',
          spl:`index=wineventlog EventCode=4769
  TicketEncryptionType=0x17
| stats count by AccountName, ServiceName, IpAddress`,
          reason:'Query too broad — BackupExec and MSSQLSvc generate hundreds of RC4 TGS requests during normal operation. Identical flood documented in TH-2026-035.',
          action:'Load SK-038 exclusion list: BackupExec/BEService, MSSQLSvc/*, WSMAN/* from Tradecraft Skills repository' },
        { num:2, badge:'PASS', metric:'7 alerts · confirmed',
          spl:`index=wineventlog EventCode=4769
  TicketEncryptionType=0x17
| where NOT match(ServiceName,"^krbtgt|^MSSQLSvc|^BackupExec|^WSMAN")
| stats count by AccountName, ServiceName, IpAddress
| where count > 3`,
          reason:'SK-038 exclusions eliminated the service account flood. 7 remaining events are interactive user sessions RC4-requesting SPNs with stale passwords — confirmed Kerberoasting candidates.' }
      ]
    }
  ],
  h03: [
    { ttp:'T1071.001', name:'C2 Beacon — JA3 fingerprint + interval regularity', finalBadge:'PASS',
      iters:[
        { num:1, badge:'FAIL', failMode:'too-many', metric:'Too many — 41,203 alerts',
          spl:`index=network sourcetype=zeek:ssl
| stats count by ja3, dest_ip, src_ip
| where count > 10`,
          reason:'Query too broad — JA3 alone covers nearly all corporate HTTPS traffic. Chrome and Edge share dozens of common fingerprints across thousands of sessions. Unusable at this volume.',
          action:'Filter to known-bad JA3 hashes from threat intel; add beacon interval regularity check' },
        { num:2, badge:'WARN', failMode:'too-many', metric:'Still too many — 48 alerts',
          spl:`index=network sourcetype=zeek:ssl
  ja3 IN ("769c10b06a1a2b7b7a26b0a2be2e88a4","1aa7bf8b9c6c3463e7785c3de70e4ec9")
| stats count, stdev(duration) as jitter, avg(duration) as avg_interval
    by src_ip, dest_ip, ja3
| where count > 5`,
          reason:'Still too many — video conferencing tools share the Cobalt Strike JA3 fingerprint. 48 sessions, can\'t triage without confirming the clock-like interval pattern of an automated beacon.',
          action:'Require stddev(interval) < 5s and ≥ 8 connections per 30-min window to confirm mechanical beaconing' },
        { num:3, badge:'PASS', metric:'2 sessions · confirmed',
          spl:`index=network sourcetype=zeek:ssl
  ja3 IN ("769c10b06a1a2b7b7a26b0a2be2e88a4","1aa7bf8b9c6c3463e7785c3de70e4ec9")
| bucket _time span=30m
| stats count, stdev(duration) as jitter by src_ip, dest_ip, ja3, _time
| where count >= 8 AND jitter < 5
| sort - count`,
          reason:'2 sessions — 185.220.101.47 on ports 443 and 8443. Intervals 60.3s/59.8s with jitter < 2s. Cobalt Strike malleable C2 profile fingerprint confirmed.' }
      ]
    }
  ]
};

// ── Per-hunt Check data — keyed by short hunt ID ──
const checkData = {
  '041': {
    hypothesis: 'H-02 · LSASS + Kerberoasting',
    queryDesc: 'Detects processes accessing LSASS memory with handles commonly used by credential dumping tools. Filters on suspicious GrantedAccess masks (0x1010, 0x1410, 0x147a, 0x1fffff) indicating full or partial LSASS read rights. Any non-AV/EDR process touching LSASS this way is anomalous.',
    querySpl: `index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe"
| where match(GrantedAccess,"0x1010|0x1410|0x147a|0x1fffff")
| stats count by _time, host, SourceImage, TargetImage, GrantedAccess, SourceProcessId
| eval severity=if(count>5,"critical","high")
| sort - count
| table _time, host, SourceImage, GrantedAccess, SourceProcessId, severity`,
    resultsMeta: '<span class="chip chip-red">3 hits</span><span class="chip chip-gray" style="font-size:10px;">0.61s</span>',
    resultsHead: '<tr><th>TimeGenerated</th><th>Host</th><th>Source Image</th><th>Access Mask</th><th>Severity</th></tr>',
    resultsBody: `<tr><td>2026-04-27 03:14</td><td>WIN-WS089</td><td style="color:var(--red);font-family:monospace;">rundll32.exe</td><td class="ttp-id">0x1fffff</td><td><span class="chip chip-red" style="font-size:10px;">critical</span></td></tr>
              <tr><td>2026-04-27 03:15</td><td>WIN-WS089</td><td style="font-family:monospace;">powershell.exe</td><td class="ttp-id">0x1010</td><td><span class="chip chip-yellow" style="font-size:10px;">high</span></td></tr>
              <tr><td>2026-04-26 22:48</td><td>WIN-DC01</td><td style="font-family:monospace;">msiexec.exe</td><td class="ttp-id">0x1410</td><td><span class="chip chip-yellow" style="font-size:10px;">high</span></td></tr>`,
    interp: '3 hits, all anomalous. <b style="color:var(--red)">rundll32.exe</b> on WIN-WS089 used a full-access handle (0x1fffff) — consistent with Mimikatz sekurlsa::logonpasswords. The subsequent powershell.exe hit on the same host 1 minute later suggests a staged dump-and-exfil sequence. WIN-DC01 msiexec hit warrants investigation — msiexec has no business accessing LSASS on a domain controller.',
    summaryPre: {
      status: 'chip-yellow', statusLabel: 'Query not run',
      tags: [
        { label: 'RAA', val: 'Partial', cls: 'chip-yellow' },
        { label: 'Query', val: 'Not run', cls: 'chip-gray' },
        { label: 'Gaps', val: 'T1558.003', cls: 'chip-yellow' },
      ],
      assessment: 'Process Chain Anomaly triggered on <b>T1003.001</b> (LSASS credential dump — WIN-WS089). However, <b>T1558.003 (Kerberoasting)</b> is outside RAA scope — TGS-REQ patterns live in authentication logs, not process chains. <b>This is a coverage gap.</b> Run the query to fill it with direct Kerberos ticket-request evidence from EventCode 4769.',
    },
    summaryPost: {
      status: 'chip-green', statusLabel: '✓ 4 rules deployed',
      tags: [
        { label: 'Subhunts', val: '4 confirmed', cls: 'chip-red' },
        { label: 'Rules', val: '4 deployed', cls: 'chip-green' },
        { label: 'Coverage', val: 'Complete', cls: 'chip-green' },
      ],
      assessment: '<b>All four subhunt detection rules validated and deployed.</b> T1570 (PsExec) confirmed — 14 correlated ADMIN$ file-drop + service-install events. T1003.001 (LSASS dump) confirmed — 5 full-access handle events matching SK-029 pattern. T1558.003 (Kerberoasting) confirmed — 3 RC4 TGS-REQ bursts from jsmith. T1071.001 (C2 beacon) confirmed — 2 Cobalt Strike sessions by JA3 + interval regularity. Credential rotation across CORP domain initiated; WIN-WS089 and WIN-DC01 isolated.',
    },
    raa: {
      relevant: true,
      analytics: [
        {
          name: 'Process Chain Anomaly',
          ttps: ['T1003.001'],
          status: 'triggered',
          hits: 1,
          findings: [
            'rundll32.exe → LSASS handle 0x1fffff — parent: explorer.exe on WIN-WS089 (not AV/EDR whitelist)',
          ],
          interp: '<b>High-confidence T1003.001.</b> <b style="color:var(--red)">rundll32.exe</b> with a full-access LSASS handle (0x1fffff) spawned from explorer.exe has no legitimate baseline. This access mask is characteristic of Mimikatz <span style="font-family:monospace;font-size:10px;">sekurlsa::logonpasswords</span>. The explorer.exe parent rules out security tooling — this is operator-driven credential dumping on WIN-WS089.',
        },
        {
          name: 'Command Line Anomaly',
          ttps: ['T1558.003'],
          status: 'partial',
          hits: 0,
          findings: [],
          interp: '<b>T1558.003 (Kerberoasting)</b> is outside Command Line Anomaly scope — TGS-REQ patterns are captured in authentication logs (EventCode 4769), not process command lines. RAA coverage for this technique is partial. The detection query directly addresses this gap.',
        },
      ],
    },
    genRules: [
      // ── Subhunt 1 · H-01 · T1570 ───────────────────────────────────────────
      {
        id: 'ck-t1570',
        hypothesis: 'H-01 · T1570 · Lateral Tool Transfer — is the adversary using PsExec to drop executables via ADMIN$ and install them as Windows services on lateral targets? ADMIN$ file-drop events alone are noisy; the detection must correlate with a same-host service install to confirm remote execution.',
        ttp: 'T1570',
        badge: 'chip-red',
        name: 'PsExec Lateral Tool Transfer — ADMIN$ drop + service install',
        ctx: 'SCCM management hosts 10.0.5.20/10.0.5.21 excluded · EventCode=5145 joined with EventCode=7045 to confirm execution followed file drop · index=windows',
        spl: `index=windows EventCode=5145 Share_Name="*ADMIN$*"
  (RelativeTargetName="*PSEXESVC*" OR RelativeTargetName="*.exe")
| where src_ip != "10.0.5.20" AND src_ip != "10.0.5.21"
| join type=inner host [
    index=windows EventCode=7045
    | rename host as host, ServiceFileName as svc_file ]
| stats count by host, src_ip, Account, svc_file`,
        finalBadge: 'PASS',
        iters: [
          {
            num: 'v1', badge: 'FAIL', failMode: 'too-many', metric: 'Too many — 2,341 alerts',
            spl: `index=windows EventCode=5145 Share_Name="*ADMIN$*"
| stats count by host, src_ip, Account`,
            reason: 'Query too broad — SCCM, Ansible, and Veeam all write to ADMIN$ constantly during patch windows. 2,341 events with no way to distinguish PsExec from legitimate IT traffic.',
            action: 'Scope to known-bad source IPs; require RelativeTargetName match on PsExec service file patterns.',
          },
          {
            num: 'v2', badge: 'WARN', failMode: 'too-many', metric: 'Still too many — 134 alerts',
            spl: `index=windows EventCode=5145 Share_Name="*ADMIN$*"
  RelativeTargetName="*PSEXESVC*" OR RelativeTargetName="*.exe"
| where src_ip != "10.0.5.20" AND src_ip != "10.0.5.21"
| stats count by host, src_ip, Account`,
            reason: 'Better, but still too noisy — legitimate admin tools also drop service executables to ADMIN$. File drop alone is not enough without confirming the executable actually ran.',
            action: 'Join with EventCode=7045 (service install) to confirm execution followed the file drop.',
          },
          {
            num: 'v3', badge: 'PASS', failMode: '', metric: '14 hits · confirmed',
            spl: `index=windows EventCode=5145 Share_Name="*ADMIN$*"
  (RelativeTargetName="*PSEXESVC*" OR RelativeTargetName="*.exe")
| where src_ip != "10.0.5.20" AND src_ip != "10.0.5.21"
| join type=inner host [
    index=windows EventCode=7045
    | rename host as host, ServiceFileName as svc_file ]
| stats count by host, src_ip, Account, svc_file`,
            reason: '14 hits — file drop correlated with service install on same host. All from non-IT source addresses (jsmith, 10.10.14.22). Analyst-reviewed and confirmed suspicious.',
            action: '',
          },
        ],
      },
      // ── Subhunt 2 · H-02 · T1003.001 ──────────────────────────────────────
      {
        id: 'ck-t1003',
        hypothesis: 'H-02 · T1003.001 · LSASS Credential Dumping — is the adversary using a credential dumping tool (e.g. Mimikatz) to extract secrets from LSASS? Focus: Sysmon EventCode=10 process-access events with full-read GrantedAccess masks on lsass.exe from non-security-tool processes.',
        ttp: 'T1003.001',
        badge: 'chip-red',
        name: 'LSASS Memory Access — full-access handle dump (SK-029)',
        ctx: 'SK-029 access-mask pattern applied · MsMpEng / CrowdStrike / SentinelOne / Velociraptor excluded · index=sysmon',
        spl: `index=sysmon EventCode=10 TargetImage="*lsass.exe*"
  GrantedAccess="0x1fffff"
| where NOT match(SourceImage,"(?i)MsMpEng|CrowdStrike|SentinelOne|velociraptor")
| stats count by SourceImage, GrantedAccess, host, user`,
        finalBadge: 'PASS',
        iters: [
          {
            num: 'v1', badge: 'FAIL', failMode: 'no-results', metric: 'No results — field not mapped',
            spl: `index=crowdstrike event_simpleName=ProcessRollup2
  TargetFileName="*lsass.exe*"
| stats count by ComputerName, UserName, CommandLine, process_handle_flags`,
            reason: 'Zero results — process_handle_flags is not available in the CIM-normalised data model. Field silently dropped at the Splunk CIM mapping layer. Query returns nothing.',
            action: 'Switch to raw Sysmon EventCode=10; use GrantedAccess field as the access-mask proxy.',
          },
          {
            num: 'v2', badge: 'FAIL', failMode: 'too-many', metric: 'Too many — 189 alerts',
            spl: `index=sysmon EventCode=10 TargetImage="*lsass.exe*"
| stats count by SourceImage, GrantedAccess, host`,
            reason: 'Query too broad — svchost.exe, MsMpEng.exe (Defender), CrowdStrike, and every other security tool on the box legitimately opens LSASS handles. 189 events, nearly all benign.',
            action: 'Apply SK-029 pattern: filter on GrantedAccess=0x1fffff (full access mask); exclude known EDR/AV process names.',
          },
          {
            num: 'v3', badge: 'PASS', failMode: '', metric: '5 hits · confirmed',
            spl: `index=sysmon EventCode=10 TargetImage="*lsass.exe*"
  GrantedAccess="0x1fffff"
| where NOT match(SourceImage,"(?i)MsMpEng|CrowdStrike|SentinelOne|velociraptor")
| stats count by SourceImage, GrantedAccess, host, user`,
            reason: '5 hits — rundll32.exe requesting full LSASS access (0x1fffff). SK-029 NtDuplicateObject pattern confirmed. No legitimate process needs this mask on a domain controller.',
            action: '',
          },
        ],
      },
      // ── Subhunt 3 · H-02 · T1558.003 ──────────────────────────────────────
      {
        id: 'ck-t1558',
        hypothesis: 'H-03 · T1558.003 · Kerberoasting — is the adversary requesting RC4-encrypted Kerberos service tickets to crack offline? Focus: EventCode=4769 TGS-REQ events with TicketEncryptionType=0x17 (RC4-HMAC downgrade) at volume anomalous for a given user.',
        ttp: 'T1558.003',
        badge: 'chip-red',
        name: 'Kerberoasting — RC4 TGS-REQ volume anomaly (SK-038)',
        ctx: 'SK-038 SPN exclusion list: BackupExec / MSSQLSvc / WSMAN pre-loaded from TH-2026-035 · threshold: >3 unique SPNs/user/5m · index=wineventlog',
        spl: `index=wineventlog EventCode=4769
    TicketEncryptionType=0x17
| bucket _time span=5m
| stats dc(ServiceName) as spn_count, values(ServiceName) as spns, count by _time, Account, src_ip
| where spn_count > 3
| where NOT match(Account,"(BackupExec|MSSQLSvc|svc_)")
| eval risk=if(spn_count>=10,"CRITICAL",if(spn_count>=5,"HIGH","MED"))
| table _time, Account, src_ip, spn_count, spns, risk`,
        finalBadge: 'PASS',
        iters: [
          {
            num: 'v1', badge: 'FAIL', failMode: 'no-results', metric: '0 results',
            spl: `index=wineventlog EventCode=4769
    TicketEncryptionType=0x23
| stats count by Account, ServiceName, src_ip`,
            reason: 'Wrong encryption type — 0x23 (AES256) filters out the RC4-downgrade tickets used in Kerberoasting. Off-line cracking requires RC4 (0x17).',
            action: 'Corrected TicketEncryptionType filter to 0x17 (RC4-HMAC).',
          },
          {
            num: 'v2', badge: 'WARN', failMode: '', metric: '31 alerts/day',
            spl: `index=wineventlog EventCode=4769
    TicketEncryptionType=0x17
| bucket _time span=5m
| stats dc(ServiceName) as spn_count, values(ServiceName) as spns, count by _time, Account, src_ip
| where spn_count > 1`,
            reason: 'Threshold too low — legitimate service accounts requesting multiple SPNs in the same window triggered 28 of 31 alerts (BackupExec, MSSQLSvc).',
            action: 'Raised threshold to >3 SPNs per 5m window; added account exclusion list from TH-2026-035.',
          },
          {
            num: 'v3', badge: 'PASS', failMode: '', metric: '3 hits · confirmed',
            spl: `index=wineventlog EventCode=4769
    TicketEncryptionType=0x17
| bucket _time span=5m
| stats dc(ServiceName) as spn_count, values(ServiceName) as spns, count by _time, Account, src_ip
| where spn_count > 3
| where NOT match(Account,"(BackupExec|MSSQLSvc|svc_)")
| eval risk=if(spn_count>=10,"CRITICAL",if(spn_count>=5,"HIGH","MED"))
| table _time, Account, src_ip, spn_count, spns, risk`,
            reason: '3 anomalous TGS-REQ bursts from non-service accounts. jsmith@corp.local — 11 unique SPNs in 5m on 2026-04-27T02:14 — CRITICAL.',
            action: '',
          },
        ],
      },
      // ── Subhunt 4 · H-03 · T1071.001 ──────────────────────────────────────
      {
        id: 'ck-t1071',
        hypothesis: 'H-04 · T1071.001 · C2 Beacon via HTTPS — is there an active command-and-control beacon using known Cobalt Strike malleable profiles? A JA3 hash alone is too broad; the key signal is mechanical regularity — low jitter, high frequency — that separates an automated beacon from human browsing.',
        ttp: 'T1071.001',
        badge: 'chip-red',
        name: 'C2 Beacon — JA3 fingerprint + interval regularity',
        ctx: 'Known Cobalt Strike JA3 hashes from threat intel · interval regularity: stddev < 5s AND ≥ 8 connections/30m · index=network (zeek:ssl)',
        spl: `index=network sourcetype=zeek:ssl
  ja3 IN ("769c10b06a1a2b7b7a26b0a2be2e88a4","1aa7bf8b9c6c3463e7785c3de70e4ec9")
| bucket _time span=30m
| stats count, stdev(duration) as jitter by src_ip, dest_ip, ja3, _time
| where count >= 8 AND jitter < 5
| sort - count`,
        finalBadge: 'PASS',
        iters: [
          {
            num: 'v1', badge: 'FAIL', failMode: 'too-many', metric: 'Too many — 41,203 alerts',
            spl: `index=network sourcetype=zeek:ssl
| stats count by ja3, dest_ip, src_ip
| where count > 10`,
            reason: 'Query too broad — JA3 alone covers nearly all corporate HTTPS traffic. Chrome and Edge share dozens of common fingerprints across thousands of sessions. Unusable at this volume.',
            action: 'Filter to known-bad JA3 hashes from threat intel; add beacon interval regularity check.',
          },
          {
            num: 'v2', badge: 'WARN', failMode: 'too-many', metric: 'Still too many — 48 alerts',
            spl: `index=network sourcetype=zeek:ssl
  ja3 IN ("769c10b06a1a2b7b7a26b0a2be2e88a4","1aa7bf8b9c6c3463e7785c3de70e4ec9")
| stats count, stdev(duration) as jitter, avg(duration) as avg_interval
    by src_ip, dest_ip, ja3
| where count > 5`,
            reason: "Still too many — video conferencing tools share the Cobalt Strike JA3 fingerprint. 48 sessions, can't triage without confirming the clock-like interval pattern of an automated beacon.",
            action: 'Require stddev(interval) < 5s and ≥ 8 connections per 30-min window to confirm mechanical beaconing.',
          },
          {
            num: 'v3', badge: 'PASS', failMode: '', metric: '2 sessions · confirmed',
            spl: `index=network sourcetype=zeek:ssl
  ja3 IN ("769c10b06a1a2b7b7a26b0a2be2e88a4","1aa7bf8b9c6c3463e7785c3de70e4ec9")
| bucket _time span=30m
| stats count, stdev(duration) as jitter by src_ip, dest_ip, ja3, _time
| where count >= 8 AND jitter < 5
| sort - count`,
            reason: '2 sessions — 185.220.101.47 on ports 443 and 8443. Intervals 60.3s/59.8s with jitter < 2s. Cobalt Strike malleable C2 profile fingerprint confirmed.',
            action: '',
          },
        ],
      },
    ],
  },
};

// ── Hunt velocity metrics ──
const velocityData = {
  '041': { mttd:'26 min', h2rule:'12 min', fpRate:'2.1%', fpTrend:'down', mttdBars:[65,48,26], fpBars:[8.3,5.2,2.1] },
  '040': { mttd:'2h 14m', h2rule:'38 min', fpRate:'8.3%', fpTrend:'up',   mttdBars:[240,150,134], fpBars:[4.1,6.9,8.3] },
  '039': { mttd:'4h 05m', h2rule:'1h 12m', fpRate:'5.2%', fpTrend:'flat', mttdBars:[310,280,245], fpBars:[6.1,5.8,5.2] },
};

// ── Finding comments (per hunt, per finding index) ──
const findingComments = {
  '041': {
    0: [ // LSASS Memory Access
      { author:'marcus',  ts:'09:44', text:'Confirmed — rundll32.exe parent was explorer.exe on WIN-DC01. Full LSASS handle. Escalating to IR now.', tag:'conf' },
      { author:'priya',   ts:'09:47', text:'Memory image requested from WIN-DC01 before any reboot. IR team notified via Slack.', tag:null },
    ],
    1: [ // PsExec lateral movement
      { author:'alice',   ts:'09:40', text:'jsmith account touched 14 hosts in one session. Isolating account pending IR review.', tag:'conf' },
    ],
    2: [ // C2 Beacon
      { author:'alice',   ts:'09:37', text:'JA3 hash 769c10… is a known Cobalt Strike malleable profile. Pushing network block to firewall now.', tag:'conf' },
      { author:'marcus',  ts:'09:52', text:'Block confirmed on perimeter FW. Beacon sessions dropped.', tag:null },
    ],
  },
  '040': {
    0: [ { author:'priya', ts:'14:25', text:'WIN-FS02 isolated by EDR. Payroll data partially encrypted — recovery from Apr 23 backup initiated.', tag:'conf' } ],
  },
};
const openFindingComments = {};  // tracks which finding comment threads are expanded

// gateDecisionLog — see kb/gate-decisions.js

// iocRepository — see kb/iocs.js
let activeIocTypeFilter   = 'all';
let activeIocStatusFilter = 'all';

// ── Archived Check data for closed hunts ──
const closedCheckSummaries = {
  '040': {
    status: 'chip-green', statusLabel: '✓ Closed — results archived',
    tags: [
      { label: 'RAA', val: 'Triggered', cls: 'chip-red' },
      { label: 'Queries', val: '2 confirmed', cls: 'chip-red' },
      { label: 'Gaps', val: 'None', cls: 'chip-green' },
    ],
    assessment: '<b>Full coverage achieved — hunt closed.</b> RAA Process Chain Anomaly confirmed the macro execution delivery chain on WIN-WS012 (T1204) and shadow copy deletion on WIN-FS02 (T1490 — anomaly score 97). Both SPL detection queries returned positive results corroborating RAA findings. Complete evidence chain handed off to IR. WIN-FS02 isolated and restored from backup.',
  },
  '039': {
    status: 'chip-green', statusLabel: '✓ Closed — results archived',
    tags: [
      { label: 'RAA', val: 'Partial', cls: 'chip-yellow' },
      { label: 'Queries', val: '2 confirmed', cls: 'chip-red' },
      { label: 'Gaps', val: 'None identified', cls: 'chip-green' },
    ],
    assessment: '<b>Full coverage achieved — RAA partial, detection queries closed all gaps.</b> Process Chain Anomaly confirmed DLL sideloading on 8 of 10 downstream hosts (T1574.002). C2 beacon detection (T1071.001) is outside RAA host-based scope — the H-02 SPL query confirmed 2 active Cobalt Strike sessions via JA3 fingerprint. Combined coverage is complete. SRV-BUILD01 re-imaged.',
  },
};

const closedRAAResults = {
  '040': {
    relevant: true,
    analytics: [
      {
        name: 'Process Chain Anomaly',
        ttps: ['T1204', 'T1490'],
        status: 'triggered',
        hits: 12,
        findings: [
          'WINWORD.EXE → cmd.exe → powershell.exe on WIN-WS012 — Office macro execution chain outside baseline',
          'vssadmin.exe delete shadows /all on WIN-FS02 — anomaly score 97, no scheduled backup in CMDB window',
        ],
        interp: '<b>High-confidence T1204 + T1490.</b> Office macro execution chain on WIN-WS012 matches FIN7 delivery TTP. Shadow copy deletion on WIN-FS02 is a definitive ransomware pre-staging indicator. RAA findings were corroborated by both SPL detection queries — full evidence chain confirmed.',
      },
    ],
  },
  '039': {
    relevant: true,
    analytics: [
      {
        name: 'Process Chain Anomaly',
        ttps: ['T1574.002'],
        status: 'triggered',
        hits: 8,
        findings: [
          'DISM.exe loading unsigned DLL from %TEMP%\\ on 8 of 10 downstream hosts — outside known-good sideloading baseline',
        ],
        interp: '<b>High-confidence T1574.002.</b> DLL sideloading via DISM.exe confirmed on 8 downstream hosts from the affected build group. Unsigned DLL path and load context match the supply-chain implant IOC profile.',
      },
      {
        name: 'Command Line Anomaly',
        ttps: ['T1071.001'],
        status: 'partial',
        hits: 0,
        findings: [],
        interp: '<b>T1071.001 (C2 via HTTPS) is outside Command Line Anomaly scope.</b> JA3/JA3S fingerprint matching requires network-layer telemetry — not process command lines. This gap was closed by the H-02 SPL query (network index), which confirmed 2 active C2 sessions to <b>update.cdn-cache[.]net</b>. RAA partial coverage here is expected and by design.',
      },
    ],
  },
};

function renderCheckSummary(postRun, dataOverride) {
  const card = document.getElementById('check-summary-card');
  if (!card) return;
  let s, subtitle;
  if (dataOverride) {
    s = dataOverride;
    subtitle = 'Archived results — hunt closed';
  } else {
    const d = checkData[_activeHuntId];
    if (!d) { card.style.display = 'none'; return; }
    s = postRun ? d.summaryPost : d.summaryPre;
    subtitle = 'Combined RAA + detection query assessment';
  }
  const tagsHTML = s.tags.map(t =>
    `<span class="chip ${t.cls}" style="font-size:10px;">${t.label}: ${t.val}</span>`
  ).join('');
  card.innerHTML = `<div class="card-head">
    <div style="display:flex;flex-direction:column;gap:2px;">
      <span class="card-title">📊 Check Summary</span>
      <span style="font-size:10px;color:var(--muted);">${subtitle}</span>
    </div>
    <span class="chip ${s.status}" style="font-size:10px;">${s.statusLabel}</span>
  </div>
  <div class="card-body">
    <div class="check-summary-tags">${tagsHTML}</div>
    <div class="check-summary-assessment">
      <span class="check-summary-assessment-label">🤖 Agent assessment</span>
      ${s.assessment}
    </div>
  </div>`;
  card.style.display = '';
}

// ── RAA (Reasoning Augmented Analytics) results — now stored in checkData[huntId].raa ──
const raaResults = {
  // legacy stub — kept for closed-hunt dataOverride path only
  h01: {
    relevant: true,
    analytics: [
      {
        name: 'Command Line Anomaly',
        ttps: ['T1570', 'T1078.002'],
        status: 'triggered',
        hits: 59,
        findings: [
          'psexesvc.exe spawned from services.exe on 3 hosts (WIN-WS089, WIN-WS102, WIN-DC01) — not in SCCM-managed task baseline',
          'wmic.exe with /node: remote target flag on CORP\\jsmith session — 14 unique remote targets in 4 h window',
          'net use \\\\&lt;target&gt;\\ipc$ with CORP\\jsmith credentials across 7 events at 02:00–04:00 UTC',
        ],
        interp: 'Command line patterns strongly confirm <b>T1570</b> (Lateral Tool Transfer) and <b>T1078.002</b> (Valid Domain Accounts). PsExec invocations are outside the SCCM-managed task baseline, and WMI remote process creation spans 14 targets in a 4-hour window — consistent with automated lateral propagation rather than manual admin activity. These results corroborate the H-01 query output and raise confidence from <i>suspicious</i> to <i>high confidence</i>.',
      },
      {
        name: 'Process Chain Anomaly',
        ttps: ['T1570', 'T1078.002'],
        status: 'triggered',
        hits: 3,
        findings: [
          'svchost.exe → powershell.exe → net.exe on WIN-DC01 — chain outside baseline for DC host class',
        ],
        interp: 'Process chain confirms post-lateral-movement execution on a domain controller. <b>svchost.exe</b> spawning PowerShell is not in this environment\'s DC host-class baseline — the chain matches a PsExec-delivered payload running discovery commands. Combined with Command Line Anomaly results, this is high-confidence <b>T1570 + T1078.002</b> activity. Recommend immediate isolation of WIN-DC01 and escalation.',
      },
    ],
  },
  h02: {
    relevant: true,
    analytics: [
      {
        name: 'Process Chain Anomaly',
        ttps: ['T1003.001'],
        status: 'triggered',
        hits: 1,
        findings: [
          'rundll32.exe → LSASS handle 0x1fffff — parent: explorer.exe on WIN-WS089 (not AV/EDR whitelist)',
        ],
        interp: '<b>High-confidence T1003.001.</b> <b style="color:var(--red)">rundll32.exe</b> with a full-access LSASS handle (0x1fffff) spawned from explorer.exe has no legitimate baseline. This access mask is characteristic of Mimikatz <span style="font-family:monospace;font-size:10px;">sekurlsa::logonpasswords</span>. The explorer.exe parent rules out security tooling — this is operator-driven credential dumping on WIN-WS089, consistent with the H-02 query results.',
      },
      {
        name: 'Command Line Anomaly',
        ttps: ['T1558.003'],
        status: 'partial',
        hits: 0,
        findings: [],
        interp: '<b>T1558.003 (Kerberoasting)</b> is outside Command Line Anomaly scope — TGS-REQ patterns are captured in authentication logs (EventCode 4769), not process command lines. RAA coverage for this technique is partial. The H-02 SPL query directly detects anomalous Kerberos ticket requests; refer to query results for T1558.003 evidence.',
      },
    ],
  },
  h03: {
    relevant: false,
    reason: 'T1071.001 (C2 via HTTPS) requires <b>network-layer telemetry</b> — JA3/JA3S fingerprints and beacon interval analysis operate on TLS handshake metadata and connection timing, which are outside Process Chain and Command Line Anomaly scope. Use the <b>H-03 SPL query</b> above for direct JA3 fingerprint matching against known Cobalt Strike malleable profiles.',
    analytics: [],
  },
};

function renderRAAResults(dataOverride) {
  const card = document.getElementById('raa-card');
  if (!card) return;
  const d = dataOverride !== undefined ? dataOverride : (checkData[_activeHuntId]?.raa || null);
  if (!d) { card.style.display = 'none'; return; }

  const statusChip = (status, hits) => {
    if (status === 'triggered') return `<span class="chip chip-red" style="font-size:10px;">⚡ Triggered &middot; ${hits} hits</span>`;
    if (status === 'partial')   return `<span class="chip chip-yellow" style="font-size:10px;">⚠ Partial coverage</span>`;
    return `<span class="chip chip-gray" style="font-size:10px;">— No coverage</span>`;
  };
  const ttpChips = (ttps) => ttps.map(t => `<span class="chip chip-indigo" style="font-size:9px;padding:1px 5px;cursor:default;" data-ttp="${t}">${t}</span>`).join('');

  let bodyHTML = '';
  if (!d.relevant) {
    bodyHTML = `<div class="raa-no-coverage">
      <span class="raa-scope-icon">🔭</span>
      <span><b style="color:var(--text);">RAA out of scope for this hypothesis</b><br>${d.reason}</span>
    </div>`;
  } else {
    bodyHTML = d.analytics.map(a => {
      const findingsHTML = a.hits > 0
        ? `<div class="raa-findings">${a.findings.map(f => `<div class="raa-finding"><span class="raa-finding-dot"></span><span>${f}</span></div>`).join('')}</div>`
        : '';
      return `<div class="raa-analytic">
        <div class="raa-analytic-head">
          <span class="raa-analytic-name">${a.name}</span>
          ${ttpChips(a.ttps)}
          ${statusChip(a.status, a.hits)}
        </div>
        ${findingsHTML}
        <div class="raa-interp">
          <div class="raa-interp-label"><span style="font-size:11px;">🤖</span> Agent interpretation</div>
          <div class="raa-interp-text">${a.interp}</div>
        </div>
      </div>`;
    }).join('');
  }

  // Build collapse summary text
  let raaSummary = 'Out of scope';
  if (d.relevant) {
    const totalHits = d.analytics.reduce((s, a) => s + (a.hits || 0), 0);
    const triggered = d.analytics.filter(a => a.status === 'triggered').length;
    raaSummary = `${d.analytics.length} analytics · ${totalHits} hits${triggered ? ' · ' + triggered + ' triggered' : ''}`;
  }

  card.innerHTML = `<div class="card-head" onclick="toggleCollapse('raa-card',event)">
    <div style="display:flex;flex-direction:column;gap:2px;">
      <span class="card-title">🔬 RAA — Reasoning Augmented Analytics</span>
      <span style="font-size:10px;color:var(--muted);">Process Chain Anomaly &middot; Command Line Anomaly</span>
    </div>
    <div style="display:flex;align-items:center;gap:6px;">
      <span class="chip chip-green" style="font-size:10px;">● Always On</span>
      <span class="card-summary">${raaSummary}</span>
      <button class="collapse-btn" onclick="toggleCollapse('raa-card',event)">▾</button>
    </div>
  </div>
  <div class="card-body" style="padding:${d.relevant ? '14px 15px' : '0'};">
    ${bodyHTML}
  </div>`;
  card.style.display = '';
}

// ── Shared helper: render det-chain HTML from a chains array ──
function _buildIterChainsHtml(chains) {
  const chipCls  = { PASS:'chip-green', WARN:'chip-yellow', FAIL:'chip-red' };
  const badgeCls = { PASS:'pass', WARN:'warn', FAIL:'fail' };
  function metricStyle(iter) {
    if (iter.badge === 'PASS') return 'color:var(--green)';
    if (iter.badge === 'WARN') return 'color:var(--yellow)';
    if (iter.failMode === 'no-results') return 'color:var(--indigo)';
    return 'color:var(--orange)';
  }
  function metricIcon(iter) {
    if (iter.badge === 'PASS') return '✓ ';
    if (iter.failMode === 'no-results') return '∅ ';
    if (iter.failMode === 'too-many') return '⚡ ';
    return '';
  }
  return chains.map(chain => `
  <div class="det-chain">
    <div class="det-chain-head" onclick="toggleDetChain(this)">
      <span class="det-chain-ttp">${chain.ttp}</span>
      <span class="det-chain-name">${chain.name}</span>
      <div class="det-chain-meta">
        <span class="chip ${chipCls[chain.finalBadge]}" style="font-size:9px;">${chain.finalBadge}</span>
        <span class="det-chain-iters">${chain.iters.length} attempt${chain.iters.length!==1?'s':''}</span>
        <span class="det-chain-chevron">▼</span>
      </div>
    </div>
    <div class="det-chain-body">
      ${chain.iters.map(iter => `
      <div class="det-iter">
        <div class="det-iter-head">
          <span class="det-iter-num">${iter.num}</span>
          <span class="det-iter-badge ${badgeCls[iter.badge]}">${iter.badge}</span>
          <span class="det-iter-fp" style="${metricStyle(iter)};font-weight:600;">${metricIcon(iter)}${iter.metric}</span>
        </div>
        <pre class="det-iter-spl">${_highlightSpl(iter.spl)}</pre>
        ${iter.reason ? `<div class="det-iter-reason">${iter.reason}</div>` : ''}
        ${iter.action ? `<div class="det-iter-action">${iter.action}</div>` : ''}
      </div>`).join('')}
    </div>
  </div>`).join('');
}

function renderGeneratedRulesCard() {
  const body = document.getElementById('generated-rules-body');
  if (!body) return;
  let rules = checkData[_activeHuntId]?.genRules || [];

  // Filter to active subhunt if one is selected
  if (typeof activeSubhunt !== 'undefined' && activeSubhunt !== 'all') {
    const shData = keepData[_activeHuntId];
    const sh = shData?.subhunts?.find(s => s.id === activeSubhunt);
    if (sh) rules = rules.filter(r => r.ttp === sh.ttp);
  }

  // Update card subtitle with live rule count
  const sub = document.getElementById('gen-rules-sub');
  if (sub) {
    sub.textContent = rules.length
      ? `${rules.length} subhunt detection rule${rules.length !== 1 ? 's' : ''} · one per TTP · ready for SIEM deployment`
      : 'No rules for selected subhunt';
  }

  body.innerHTML = rules.map((r, idx) => {
    const isLast = idx === rules.length - 1;
    const iterHtml = (r.iters && r.iters.length)
      ? `<div style="margin-top:8px;">
           <div style="font-size:10px;color:var(--muted);margin-bottom:4px;display:flex;align-items:center;gap:6px;">
             <span style="color:var(--sub);">⚙ Detection Logic Agent</span>
             <span style="color:var(--border2);">·</span>
             <span>${r.iters.length} refinement attempt${r.iters.length !== 1 ? 's' : ''}</span>
           </div>
           ${_buildIterChainsHtml([{ ttp: r.ttp, name: r.name, finalBadge: r.finalBadge, iters: r.iters }])}
         </div>`
      : '';
    const hypHtml = r.hypothesis
      ? `<div class="context-annotation" style="background:rgba(99,102,241,.07);border-left-color:var(--indigo);margin-bottom:6px;">
           <span class="ca-label" style="color:var(--indigo);">💡 Hypothesis</span>
           <span>${r.hypothesis}</span>
         </div>`
      : '';
    return `
    <div style="${isLast ? '' : 'padding-bottom:18px;border-bottom:1px solid var(--border);margin-bottom:18px;'}">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
        <span class="chip chip-indigo" style="font-size:10px;padding:1px 6px;">${r.ttp}</span>
        <span class="chip chip-green" style="font-size:10px;">${r.finalBadge}</span>
        <span style="font-size:12px;color:var(--text);font-weight:600;">${r.name}</span>
      </div>
      ${hypHtml}
      <div class="context-annotation"><span class="ca-label">⚙ Context applied</span><span>${r.ctx}</span></div>
      <div class="feed-spl">
        <div class="feed-spl-head">
          <span class="feed-spl-label">SPL · ${r.ttp}</span>
          <button class="spl-copy" id="chk-cp-${r.id}">copy</button>
        </div>
        <pre class="feed-spl-pre" id="chk-pre-${r.id}">${_highlightSpl(r.spl)}</pre>
      </div>
      ${iterHtml}
      <button class="rule-test-btn" id="chk-rtb-${r.id}" onclick="runRuleTest(this,'${r.id}')">▶ Run Test</button>
      <div class="rule-test-panel" id="test-panel-${r.id}"></div>
    </div>`;
  }).join('');
  // Wire up copy buttons (after HTML is in DOM)
  rules.forEach(r => {
    const btn = document.getElementById('chk-cp-' + r.id);
    if (btn) btn.addEventListener('click', () => _copySpl(btn, r.spl));
  });
}

// ── Top-level init ──
renderCheckSummary(true);
renderRAAResults();
renderGeneratedRulesCard();
