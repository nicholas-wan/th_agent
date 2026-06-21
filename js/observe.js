/* ── observe.js ───────────────────────────────────────────────────────────
   Hunt Observe stage functions. Loaded after app.js.
   ──────────────────────────────────────────────────────────────────────── */

let observeCurrentScope = null;
const observeEditCards = { normal: false, suspicious: false };

// ── Hunt Observe ──
const observeData = {
  '041': {
    normal: [
      { text: 'SCCM ConfigMgr_* scheduled tasks created by msiexec or sccm services — established baseline exclusion (TH-2025-091 · Alice)' },
      { text: 'AV/EDR agents (Carbon Black, CrowdStrike) accessing LSASS with stable, known PIDs — expected system behaviour' },
      { text: 'Kerberos TGS-REQs for BackupExec and MSSQLSvc SPNs from backup service accounts — known SPN list (TH-2026-035 · Marcus)' },
      { text: 'IT admin accounts using PSRemoting/WinRM during business hours (06:00–22:00 UTC) from approved jump hosts' },
      { text: 'Batch jobs on DB-SRV-02 and DB-SRV-03 running 02:00–04:00 UTC — time-boxed exclusion (TH-2026-038 · Priya)' },
      { text: 'svchost.exe spawning child processes within known Windows service host patterns on workstation-class hosts' },
    ],
    suspicious: [
      { text: 'Single domain account authenticating to 3 or more distinct hosts outside 06:00–22:00 UTC — lateral movement indicator' },
      { text: 'Non-AV/EDR process (rundll32.exe, explorer.exe) accessing LSASS with handle 0x1fffff — credential harvesting pattern' },
      { text: 'TGS-REQ volume ≥ 3 distinct SPNs within 5 minutes from a single source IP — Kerberoasting pattern' },
      { text: 'schtasks.exe /create with powershell, cmd, wscript, or rundll32 in the task command — persistence via scripting engine' },
      { text: 'Registry Run key modifications by processes outside the approved software baseline — persistence indicator' },
      { text: 'Outbound HTTPS with 58–62s beacon interval matching Cobalt Strike JA3 profile — C2 beaconing pattern' },
    ],
    observables: {
      Processes: ['psexesvc.exe', 'wmic.exe with /node: remote target', 'schtasks.exe /create', 'rundll32.exe accessing LSASS', 'cmd.exe /c whoami (post-lateral)'],
      Network: ['JA3: 769c10b06a1a2b7b7a26b0a2be2e88a4 (Cobalt Strike profile)', '185.220.101.47:443 and :8443', 'Beacon interval 60s ± 2s', 'Dual-port primary + fallback C2 channel'],
      Files: ['New scheduled tasks outside SCCM namespace', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MicrosoftEdgeUpdate', 'LSASS minidump in %TEMP% or C:\\ProgramData\\', 'Staging files in non-standard locations'],
      Authentication: ['Off-hours NTLM/Kerberos from CORP\\jsmith', 'Lateral auth via ADMIN$ across 14 hosts', 'TGS-REQ spike — 11 SPNs within 5 min (T1558.003)'],
    },
    subhunts: {
      sh01: {
        label: 'SH-01 · T1570 · Lateral Tool Transfer', ttpChip: 'chip-red',
        normal: [
          { text: 'SCCM-initiated PsExec or remote service installs from SCCM server (10.0.5.11) — signed service binaries, EventCode 7045 from SCCM account only' },
          { text: 'IT admin PSRemoting/WinRM sessions from approved jump hosts (10.0.8.0/24) during business hours 06:00–22:00 UTC' },
          { text: 'Scheduled ADMIN$ file copies from backup service account (svc-backup) during maintenance window 02:00–04:00 UTC' },
          { text: 'Named pipe connections on \\pipe\\svcctl or \\pipe\\winreg from domain admin accounts in approved console sessions' },
        ],
        suspicious: [
          { text: 'psexesvc.exe or ADMIN$ file drop originating from a workstation IP — lateral movement not initiated by SCCM or jump host' },
          { text: 'New service installation (EventCode 7045) outside SCCM namespace by a user-class or compromised account' },
          { text: 'Named pipe relay over \\pipe\\svcctl forming a hop chain — more than 2 lateral hops within 10 minutes' },
          { text: 'CORP\\jsmith authenticating to 3+ distinct hosts via NTLM/Kerberos outside 06:00–22:00 UTC — confirmed off-hours pattern' },
          { text: 'EventCode 5145 (network share access) targeting ADMIN$ or C$ from a non-admin workstation account' },
        ],
        observables: {
          'Key Events': ['EventCode 5145 — ADMIN$ share access from workstation IP', 'EventCode 7045 — new service created outside SCCM namespace', 'EventCode 4624 Type 3 — NTLM lateral logon off-hours'],
          Processes: ['psexesvc.exe dropped on remote target host', 'cmd.exe /c net use \\\\target\\ADMIN$', 'svcctl service install chain from CORP\\jsmith'],
          Network: ['SMB port 445 from workstation → server ADMIN$', 'Named pipe relay \\pipe\\svcctl across 14-host chain'],
          Authentication: ['CORP\\jsmith — 14-host pivot chain confirmed (TH-2026-038 overlap)', 'Off-hours Kerberos TGS-REQ 23:17–01:42 UTC'],
        }
      },
      sh02: {
        label: 'SH-02 · T1003.001 · LSASS Credential Dumping', ttpChip: 'chip-red',
        normal: [
          { text: 'CrowdStrike (csagent.sys, csfalconservice.exe) and Windows Defender (MsMpEng.exe) accessing lsass.exe with stable known PIDs — expected EDR behaviour' },
          { text: 'Windows system processes (winlogon.exe, lsm.exe, services.exe) holding known read-only handles on lsass.exe at boot' },
          { text: 'LSASS restarts during Windows Update cycles in approved maintenance window (02:00–04:00 UTC Sunday)' },
        ],
        suspicious: [
          { text: 'Non-AV/EDR process opening lsass.exe with PROCESS_ALL_ACCESS (GrantedAccess 0x1fffff) — full credential dump access' },
          { text: 'rundll32.exe, cmd.exe, or explorer.exe as source image in Sysmon EventCode=10 targeting lsass.exe' },
          { text: 'Unsigned or LOLBin process holding LSASS handle on WIN-DC01 — Tier-0 DC is the highest-value credential store' },
          { text: 'LSASS minidump file (.dmp or .mdmp) created in %TEMP%, %APPDATA%, or C:\\ProgramData\\ by a non-system process' },
          { text: 'Sysmon EventCode=10 burst on WIN-DC01 within the CORP\\jsmith session window (23:17–01:42 UTC)' },
        ],
        observables: {
          'Key Events': ['Sysmon EventCode=10 · TargetImage=lsass.exe · GrantedAccess=0x1fffff · SourceImage ∉ AV baseline', 'EventCode 4673 — sensitive privilege use (SeDebugPrivilege) on WIN-DC01'],
          Processes: ['rundll32.exe (PID 7340) — PROCESS_ALL_ACCESS on lsass.exe at 01:38:22 UTC', 'Process chain: explorer.exe → cmd.exe (4812) → rundll32.exe (7340)'],
          Files: ['lsass.dmp / sekurlsa.log artifact in %TEMP% or C:\\ProgramData\\', 'Mimikatz or reflective DLL in non-standard path'],
          Host: ['WIN-DC01 (10.0.1.10) — Tier-0 DC · primary target · SK-029 exclusions scoped to this host'],
        }
      },
      sh03: {
        label: 'SH-03 · T1558.003 · Kerberoasting', ttpChip: 'chip-red',
        normal: [
          { text: 'BackupExec service account (svc-backup$) requesting TGS tickets for registered backup SPNs — RC4 expected, scheduled (02:00–04:00 UTC)' },
          { text: 'MSSQLSvc/* SPN requests from SQL service accounts during DB startup and replication — on schedule, single SPN per request' },
          { text: 'DC replication Kerberos events (DomainDNSZones, GC) during maintenance window — known source IPs only' },
        ],
        suspicious: [
          { text: 'Single user account requesting RC4-encrypted TGS tickets for 3+ distinct SPNs within 5 minutes — targeted kerberoasting pattern' },
          { text: 'TGS-REQ for high-privilege SPN (krbtgt, HTTP/intranet, RPCSS) from a standard domain user account — Golden Ticket pre-staging' },
          { text: 'RC4 TGS-REQ volume well above the per-account 3σ daily baseline outside the scheduled backup window — threshold set post-SPN-exclusion' },
          { text: 'TGS request for SPNs not in the 147-entry CMDB exclusion list from a non-service account — likely targeted enumeration' },
        ],
        observables: {
          'Key Events': ['EventCode 4769 · TicketEncryptionType=0x17 (RC4) · ServiceName ∉ 147-SPN exclusion list', 'EventCode 4768 burst — multiple Kerberos AS-REQ from single account in short window'],
          Account: ['CORP\\jsmith — 11 distinct SPN requests in 5 min including krbtgt (23:17 UTC)', 'SPNs targeted: krbtgt/CORP, MSSQLSvc/WIN-SQL02:1433, HTTP/intranet.corp.local'],
          'Detection Tuning': ['RC4 burst threshold: >3 SPNs/user/5m · 147 CMDB SPN exclusions loaded (BackupExec + MSSQLSvc)', 'FP rate dropped from 22% (TH-2026-035) to <2% after exclusion list applied'],
          Network: ['Kerberos traffic to WIN-DC01 (10.0.1.10) from workstation CORP\\jsmith source host'],
        }
      },
      sh04: {
        label: 'SH-04 · T1071.001 · C2 Beacon via HTTPS', ttpChip: 'chip-indigo',
        normal: [
          { text: 'Browser HTTPS to Microsoft 365, Akamai CDN, and approved SaaS endpoints — stable JA3 profiles, cert chains rooted in DigiCert or Sectigo' },
          { text: 'CrowdStrike and Microsoft ATP cloud connectivity — known destination IPs, cert lifetime > 30 days, regular EDR heartbeat interval' },
          { text: 'Office application HTTPS telemetry to Microsoft endpoints — variable interval, approved user-agent strings' },
        ],
        suspicious: [
          { text: 'HTTPS beacon with stdev < 5s on 58–62s interval to non-approved external IP — Cobalt Strike default profile signature' },
          { text: 'JA3 fingerprint 769c10b06a1a2b7b7a26b0a2be2e88a4 matching known Cobalt Strike malleable C2 profiles' },
          { text: 'Short-lived Let\'s Encrypt certificate (lifetime < 24hr) with non-browser or empty user-agent string to external IP' },
          { text: 'Outbound HTTPS to ASN associated with VPS/hosting infrastructure (Frantech, Mullvad, AS62160) with no prior baseline' },
          { text: 'Dual-port C2 channel: primary :443 + fallback :8443 to same destination IP with identical beacon timing' },
        ],
        observables: {
          Network: ['185.220.101.47:443 — JA3 769c10b06a1a2b7b7a26b0a2be2e88a4 · beacon 60.1s ±0.3s stdev', '185.220.101.47:8443 — fallback C2 channel, identical JA3 + timing'],
          Certificate: ['CN=update.windows-cdn[.]net · Let\'s Encrypt · issued < 24hr · 1 SAN · not in approved cert baseline'],
          'Detection Path': ['JA3 fingerprint match (Zeek SSL log)', 'Beacon interval regularity: stdev < 5s over 30-min window', 'Short cert lifetime + non-browser UA string in HTTP log'],
          'Prior Hunt': ['TH-2025-091 — zero JA3 hits · net-new cert-chain path not previously hunted · Alice Chen flagged gap'],
        }
      },
    }
  },
  '042': {
    normal: [
      { text: 'Domain Admin accounts authenticate to DCs during scheduled maintenance windows (02:00–04:00 UTC)' },
      { text: 'AD replication traffic between WIN-DC01 and WIN-DC02 via DRS protocol — expected inter-DC sync' },
      { text: 'SPN registration changes via SCCM service account during software deployment cycles' },
      { text: 'EventCode 4672 special privilege logons from IT admin accounts during business hours' },
    ],
    suspicious: [
      { text: 'EventCode 4662 with DS-Replication-Get-Changes extended rights from a non-DC source — DCSync indicator' },
      { text: 'New SPN registrations on Domain Admin or Tier-0 service accounts outside change-control windows' },
      { text: 'EventCode 4672 special privilege logon from workstation-class hosts to DCs outside maintenance windows' },
      { text: 'AD delegation modifications granting replication rights to non-standard accounts' },
    ],
    observables: {
      Processes: ['mimikatz.exe or lsadump::dcsync invocation', 'ntdsutil.exe with ifm parameter', 'secretsdump.py or equivalent'],
      Network: ['DRS replication traffic from non-DC source IP', 'LDAP queries for replication metadata from workstation subnet'],
      Authentication: ['CORP\\jsmith 4672 logons on WIN-DC01 in 72h window', 'Any non-admin account with Replicating Directory Changes rights'],
      'AD Changes': ['New SPN registrations on Tier-0 accounts', 'Delegation changes granting DS-Replication-Get-Changes', 'msDS-AllowedToDelegateTo modifications'],
    },
    subhunts: {
      sh01: {
        label: 'SH-01 · T1078.002 · Privileged Account Abuse', ttpChip: 'chip-yellow',
        normal: [
          { text: 'Domain Admin and Server Admin accounts log on to WIN-DC01/WIN-DC02 from approved jump hosts during 02:00-04:00 UTC maintenance windows.' },
          { text: 'EventCode 4672 special privilege logons from IT admin groups are expected when paired with approved change tickets and source hosts in the admin VLAN.' },
          { text: 'Service accounts used by backup, monitoring, and SCCM may request privileged sessions to DCs only from registered service hosts.' },
          { text: 'CORP\\jsmith has prior administrative activity in TH-2026-041, but normal activity should not originate from workstation-class hosts or outside the approved window.' },
          { text: 'Kerberos/NTLM authentication to Tier-0 assets should have a matching interactive admin session, ticket, or privileged access management checkout.' },
        ],
        suspicious: [
          { text: 'EventCode 4672 special privilege logon to WIN-DC01 from a workstation-class source without a matching PAM checkout or change ticket.' },
          { text: 'Privileged account reuse within 72 hours of the TH-2026-041 CORP\\jsmith lateral movement chain.' },
          { text: 'Domain Admin authentication to multiple Tier-0 hosts from the same source within a short window, especially outside 06:00-22:00 UTC.' },
          { text: 'Logon Type 3 or 10 to a DC followed by LDAP enumeration, replication-rights checks, or SPN/delegation queries.' },
          { text: 'A privileged logon that is not followed by expected admin tooling such as MMC, PowerShell remoting from jump hosts, or approved backup activity.' },
        ],
        observables: {
          Authentication: ['EventCode 4672 special privileges assigned', 'EventCode 4624 Type 3/10 to WIN-DC01', 'Source host class and admin VLAN membership'],
          Accounts: ['CORP\\jsmith', 'Domain Admins members', 'Tier-0 service accounts'],
          Context: ['PAM checkout records', 'change-ticket window', 'approved jump host list'],
        }
      },
      sh02: {
        label: 'SH-02 · T1484.001 · Domain Policy Modification', ttpChip: 'chip-yellow',
        normal: [
          { text: 'GPO and delegation changes are performed by AD engineering accounts during approved weekly change windows with matching ticket IDs.' },
          { text: 'SPN registration changes are expected from SCCM and application deployment service accounts during documented software rollouts.' },
          { text: 'Tier-0 OU ACL updates are rare and should be paired with administrative console activity from approved management hosts.' },
          { text: 'msDS-AllowedToDelegateTo changes normally occur only for pre-approved service accounts and are recorded in the AD change log.' },
          { text: 'Replication-rights assignments are limited to DC computer accounts and designated directory synchronization services.' },
        ],
        suspicious: [
          { text: 'New or modified SPN on a Domain Admin, Tier-0 service account, or account touched by the TH-2026-041 pivot chain.' },
          { text: 'GPO, OU ACL, or delegation modification outside the change window or from a non-AD engineering account.' },
          { text: 'Granting GenericAll, WriteDACL, WriteOwner, or replication-related rights to a user or workstation account.' },
          { text: 'msDS-AllowedToDelegateTo or TrustedToAuthForDelegation changes that broaden access to DC, LDAP, CIFS, or HOST services.' },
          { text: 'A policy or delegation change shortly after privileged-account logon activity on WIN-DC01.' },
        ],
        observables: {
          'AD Changes': ['EventCode 5136 directory object modified', 'EventCode 4739 domain policy changed', 'SPN add/remove events'],
          Attributes: ['servicePrincipalName', 'msDS-AllowedToDelegateTo', 'nTSecurityDescriptor', 'userAccountControl'],
          Scope: ['Tier-0 OUs', 'Domain Admin accounts', 'DC computer objects'],
        }
      },
      sh03: {
        label: 'SH-03 · T1003.006 · DCSync', ttpChip: 'chip-red',
        normal: [
          { text: 'DRS replication is expected only between WIN-DC01 and WIN-DC02 using DC computer accounts and known inter-DC network paths.' },
          { text: 'Directory synchronization services may request replication metadata only from registered sync servers and approved service accounts.' },
          { text: 'EventCode 4662 replication-rights access is normal for DC-to-DC activity when the source host is a domain controller.' },
          { text: 'Backup and identity tooling may query AD metadata, but should not request DS-Replication-Get-Changes-All from workstation subnets.' },
          { text: 'Replication traffic should align with known DC IPs, scheduled sync intervals, and expected RPC/LDAP service access patterns.' },
        ],
        suspicious: [
          { text: 'EventCode 4662 with DS-Replication-Get-Changes or DS-Replication-Get-Changes-All from a non-DC source host.' },
          { text: 'DRSUAPI or replication RPC activity initiated by a user account, workstation, jump host, or recently compromised source.' },
          { text: 'Replication-rights access shortly after privileged-account abuse or delegation/SPN modification in the same 72-hour window.' },
          { text: 'Use of secretsdump.py, mimikatz lsadump::dcsync, or equivalent behavior without an obvious process artifact on a DC.' },
          { text: 'A non-DC account enumerating domain replication metadata and then accessing krbtgt, admin, or Tier-0 credential material.' },
        ],
        observables: {
          'Key Events': ['EventCode 4662 with replication GUIDs', 'DS-Replication-Get-Changes-All', 'Directory Service Access audit events'],
          Network: ['DRSUAPI RPC from non-DC source', 'LDAP replication metadata queries', 'unexpected DC endpoint mapper sessions'],
          Accounts: ['Non-DC computer accounts', 'privileged users from TH-2026-041', 'newly delegated accounts'],
        }
      },
    }
  },
  '040': {
    normal: [
      { text: 'Office macros signed by the enterprise CA root — expected for Finance department document automation workflows' },
      { text: 'Scheduled Volume Shadow Copy operations from backup software during maintenance windows' },
      { text: 'DISM.exe loading signed Microsoft DLLs for OS servicing and Windows Update operations' },
      { text: 'LSASS access from known AV/EDR processes only — CrowdStrike, Windows Defender with stable PIDs' },
      { text: 'Outbound HTTPS from Office applications to Microsoft 365 endpoints (known CDN IPs)' },
    ],
    suspicious: [
      { text: 'Unsigned Office macros executing — especially macros that spawn PowerShell, cmd.exe, or WScript' },
      { text: 'vssadmin.exe delete shadows /all — ransomware pre-deployment staging, shadow copy deletion' },
      { text: 'DISM.exe loading DLLs not in the Windows signed binary catalogue — DLL sideloading' },
      { text: 'LSASS access from non-system processes with unusual parent (e.g. WINWORD.exe → powershell.exe)' },
      { text: 'File encryption activity — mass modification of documents with entropy spike in I/O patterns' },
    ],
    observables: {
      Processes: ['WINWORD.exe spawning PowerShell', 'vssadmin.exe delete shadows', 'DISM.exe with unsigned DLL load', 'Ransomware binary (FIN7 tooling)'],
      Network: ['Outbound to FIN7 C2 infrastructure', 'Suspicious TLS certificates (self-signed)', 'Data exfil before encryption (double-extortion pattern)'],
      Files: ['Unsigned Office macro files', 'Shadow copy deletion event logs', 'DLL sideload files in DISM directory', 'Ransom note (README.txt / RECOVERY.txt)'],
      Authentication: ['Finance user accounts with unusual access patterns', 'Compromised credentials reused from WIN-WS012'],
    }
  },
  '039': {
    normal: [
      { text: 'CI/CD build artifacts signed by the corporate code-signing certificate — verified against artifact registry on publish' },
      { text: 'Scheduled build tasks created by the CI/CD service account (svc-build) from the approved build server only' },
      { text: 'DLL loads on downstream hosts matching the signed artifact registry hash list' },
      { text: 'Outbound HTTPS from SRV-BUILD01 to known package registries (npm, PyPI, Maven) during build windows' },
    ],
    suspicious: [
      { text: 'Unsigned binaries published to the artifact repository — does not match any registered build output hash' },
      { text: 'Scheduled task named svchost or similar system-sounding name created by the build service account' },
      { text: 'DLL load on downstream host not matching the signed artifact hash — potential sideload payload' },
      { text: 'Outbound HTTPS from SRV-BUILD01 to non-registry endpoints with beacon-like intervals' },
      { text: 'Cobalt Strike JA3 fingerprint on outbound connections from build or downstream hosts' },
    ],
    observables: {
      Processes: ['Unsigned build artifact binary', 'svchost-wrapper scheduled task', 'DLL sideload via legitimate Windows binary'],
      Network: ['JA3 match to Cobalt Strike (update.cdn-cache[.]net)', 'HTTPS beacon from build/downstream hosts', 'Exfil over C2 channel (T1041)'],
      Files: ['Unsigned binary introduced Apr 10', 'svchost-wrapper scheduled task XML', 'DLL sideload files on downstream hosts (10 hosts)'],
      Authentication: ['svc-build account used outside build windows', 'Downstream host auth anomalies post-infection'],
    }
  },
};

// ── Helpers ──
function _derivedObserveProfile(id, shId) {
  const kd = (typeof keepData !== 'undefined') ? keepData[id] : null;
  const keepSh = shId ? kd?.subhunts?.find(sh => sh.id === shId) : null;
  const lockSh = shId ? kd?.subhuntLock?.[shId] : null;
  if (!keepSh || !lockSh) return null;
  return {
    label: `${keepSh.label} · ${keepSh.ttp} · ${keepSh.name}`,
    ttpChip: keepSh.ttp.includes('1071') ? 'chip-indigo' : keepSh.ttp.includes('1484') ? 'chip-yellow' : 'chip-red',
    normal: [
      { text: `Expected baseline review for ${keepSh.name}: validate known-good activity before escalating ${keepSh.ttp}.` },
      { text: lockSh.l },
    ],
    suspicious: [
      { text: lockSh.o },
      { text: lockSh.c },
    ],
    observables: {
      Technique: [`${keepSh.ttp} · ${keepSh.name}`, `${keepSh.status.charAt(0).toUpperCase() + keepSh.status.slice(1)} subhunt status`],
      'Observe Focus': [lockSh.o],
      'Check Focus': [lockSh.c],
    },
  };
}

function _obsTarget(id) {
  const huntData = observeData[id];
  if (!huntData) return null;
  const shId = (typeof activeSubhunt !== 'undefined' && activeSubhunt) ? activeSubhunt : null;
  if (shId && !huntData.subhunts) huntData.subhunts = {};
  if (shId && !huntData.subhunts[shId]) {
    const derived = _derivedObserveProfile(id, shId);
    if (derived) huntData.subhunts[shId] = derived;
  }
  const shData = (shId && huntData.subhunts && huntData.subhunts[shId]) ? huntData.subhunts[shId] : null;
  return { huntData, shData, d: shData || huntData };
}

function _catDomId(cat) {
  return 'obs-add-obs-' + cat.replace(/[^a-zA-Z0-9]/g, '-');
}

function _obsFieldValue(text) {
  return String(text || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function _obsHtml(text) {
  return _obsFieldValue(text);
}

function toggleObserveCardEdit(id, card) {
  saveObserveEdits(id);
  observeEditCards[card] = !observeEditCards[card];
  renderHuntObserve(id);
}

// ── Save all in-progress input edits back to data before any re-render ──
function saveObserveEdits(id) {
  const t = _obsTarget(id);
  if (!t) return;
  // Normal inputs
  document.querySelectorAll('.obs-normal-input').forEach(inp => {
    const idx = parseInt(inp.dataset.idx, 10);
    if (!isNaN(idx) && t.d.normal[idx]) {
      const v = inp.value.trim();
      if (v) t.d.normal[idx].text = v;
    }
  });
  // Suspicious inputs
  document.querySelectorAll('.obs-susp-input').forEach(inp => {
    const idx = parseInt(inp.dataset.idx, 10);
    if (!isNaN(idx) && t.d.suspicious[idx]) {
      const v = inp.value.trim();
      if (v) t.d.suspicious[idx].text = v;
    }
  });
  // Observable inputs
  document.querySelectorAll('.obs-obs-input').forEach(inp => {
    const cat = inp.dataset.cat;
    const idx = parseInt(inp.dataset.idx, 10);
    if (cat && !isNaN(idx) && t.d.observables[cat] && t.d.observables[cat][idx] !== undefined) {
      const v = inp.value.trim();
      if (v) t.d.observables[cat][idx] = v;
    }
  });
}

// ── Normal item CRUD ──
function obsDeleteNormal(id, idx) {
  saveObserveEdits(id);
  const t = _obsTarget(id);
  if (!t) return;
  t.d.normal.splice(idx, 1);
  renderHuntObserve(id);
}

function obsAddNormal(id) {
  saveObserveEdits(id);
  const t = _obsTarget(id);
  if (!t) return;
  const input = document.getElementById('obs-add-normal-input');
  const val = input && input.value.trim();
  if (!val) return;
  t.d.normal.push({ text: val });
  renderHuntObserve(id);
}

// ── Suspicious item CRUD ──
function obsDeleteSuspicious(id, idx) {
  saveObserveEdits(id);
  const t = _obsTarget(id);
  if (!t) return;
  t.d.suspicious.splice(idx, 1);
  renderHuntObserve(id);
}

function obsAddSuspicious(id) {
  saveObserveEdits(id);
  const t = _obsTarget(id);
  if (!t) return;
  const input = document.getElementById('obs-add-susp-input');
  const val = input && input.value.trim();
  if (!val) return;
  t.d.suspicious.push({ text: val });
  renderHuntObserve(id);
}

// ── Observable item CRUD ──
function obsDeleteObservable(id, cat, idx) {
  saveObserveEdits(id);
  const t = _obsTarget(id);
  if (!t || !t.d.observables[cat]) return;
  t.d.observables[cat].splice(idx, 1);
  renderHuntObserve(id);
}

function obsAddObservable(id, cat) {
  saveObserveEdits(id);
  const t = _obsTarget(id);
  if (!t) return;
  const input = document.getElementById(_catDomId(cat));
  const val = input && input.value.trim();
  if (!val) return;
  if (!t.d.observables[cat]) t.d.observables[cat] = [];
  t.d.observables[cat].push(val);
  renderHuntObserve(id);
}

function obsDeleteCategory(id, cat) {
  saveObserveEdits(id);
  const t = _obsTarget(id);
  if (!t || !t.d.observables) return;
  delete t.d.observables[cat];
  renderHuntObserve(id);
}

function obsAddCategory(id) {
  saveObserveEdits(id);
  const t = _obsTarget(id);
  if (!t) return;
  const input = document.getElementById('obs-add-cat-input');
  // Strip single quotes to keep inline onclick safe
  const val = input && input.value.trim().replace(/'/g, '');
  if (!val) return;
  if (!t.d.observables[val]) t.d.observables[val] = [];
  input.value = '';
  renderHuntObserve(id);
}

function renderHuntObserve(id) {
  const huntData = observeData[id];
  const main = document.getElementById('obs-main-body');
  const side = document.getElementById('obs-side-body');
  if (!main || !side) return;
  if (!huntData) {
    main.innerHTML = `<div class="info-bar"><span class="ib-icon">ℹ️</span><span>No observe profile available for this hunt yet.</span></div>`;
    side.innerHTML = '';
    return;
  }

  // Resolve subhunt-specific data if a subhunt is selected
  const shId = (typeof activeSubhunt !== 'undefined' && activeSubhunt) ? activeSubhunt : null;
  const scopeKey = `${id}:${shId || 'hunt'}`;
  if (scopeKey !== observeCurrentScope) {
    observeCurrentScope = scopeKey;
    observeEditCards.normal = false;
    observeEditCards.suspicious = false;
  }
  if (shId && !huntData.subhunts) huntData.subhunts = {};
  if (shId && !huntData.subhunts[shId]) {
    const derived = _derivedObserveProfile(id, shId);
    if (derived) huntData.subhunts[shId] = derived;
  }
  const shData = (shId && huntData.subhunts && huntData.subhunts[shId]) ? huntData.subhunts[shId] : null;
  const d = shData || huntData;
  const reasoningBtn = `<button onclick="openAgentReasoning('hyp')">View reasoning</button>`;
  const editingNormal = !!observeEditCards.normal;
  const editingSuspicious = !!observeEditCards.suspicious;

  // Subhunt context banner
  const subhuntBannerHTML = shData ? `
    <div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:rgba(59,130,246,.06);border:1px solid rgba(59,130,246,.2);border-radius:var(--radius-sm);margin-bottom:10px;">
      <span style="font-size:11px;color:var(--muted);">Observe profile for</span>
      <span class="chip ${shData.ttpChip}" style="font-size:10px;">${shData.label}</span>
    </div>` : '';

  // ── Normal items ──
  const normalItemsHTML = d.normal.map((n, idx) => `
    <div class="obs-item">
      <span class="obs-item-icon" style="color:var(--green);">✓</span>
      ${editingNormal
        ? `<textarea class="obs-edit-input obs-inline-field obs-normal-input" rows="2" onblur="saveObserveEdits('${id}')" data-idx="${idx}">${_obsFieldValue(n.text)}</textarea>
           <button class="obs-delete-btn" onclick="obsDeleteNormal('${id}',${idx})" title="Remove">✕</button>`
        : `<span style="flex:1;">${_obsHtml(n.text)}</span>`}
    </div>`).join('') || `<div class="obs-empty-state">No baseline patterns yet.</div>`;

  const normalAddHTML = editingNormal ? `
    <div class="obs-add-row">
      <input class="obs-add-input" id="obs-add-normal-input" placeholder="Add baseline pattern…"
             onkeydown="if(event.key==='Enter')obsAddNormal('${id}')">
      <button class="obs-add-btn" onclick="obsAddNormal('${id}')">+ Add</button>
    </div>` : '';

  // ── Suspicious items ──
  const suspItemsHTML = d.suspicious.map((s, idx) => `
    <div class="obs-item">
      <span class="obs-item-icon" style="color:var(--yellow);">⚠</span>
      ${editingSuspicious
        ? `<textarea class="obs-edit-input obs-inline-field obs-susp-input" rows="2" onblur="saveObserveEdits('${id}')" data-idx="${idx}">${_obsFieldValue(s.text)}</textarea>
           <button class="obs-delete-btn" onclick="obsDeleteSuspicious('${id}',${idx})" title="Remove">✕</button>`
        : `<span style="flex:1;">${_obsHtml(s.text)}</span>`}
    </div>`).join('') || `<div class="obs-empty-state">No adversary patterns yet.</div>`;

  const suspAddHTML = editingSuspicious ? `
    <div class="obs-add-row">
      <input class="obs-add-input" id="obs-add-susp-input" placeholder="Add adversary pattern…"
             onkeydown="if(event.key==='Enter')obsAddSuspicious('${id}')">
      <button class="obs-add-btn" onclick="obsAddSuspicious('${id}')">+ Add</button>
    </div>` : '';

  main.innerHTML = `
    ${subhuntBannerHTML}
    <div class="card">
      <div class="card-head">
        <span class="card-title">✅ What Normal Looks Like</span>
        <div class="obs-head-actions">
          <span class="chip chip-green" style="font-size:10px;">${d.normal.length} baseline pattern${d.normal.length !== 1 ? 's' : ''}</span>
          <button class="obs-edit-card-btn${editingNormal ? ' on' : ''}" onclick="toggleObserveCardEdit('${id}','normal')" title="${editingNormal ? 'Done editing' : 'Edit normal patterns'}">✎</button>
        </div>
      </div>
      <div class="card-body" style="padding:8px 14px;">
        <div class="section-agent-line" style="margin-bottom:8px;"><b>💡 Hypothesis Agent</b><span>What Normal Looks Like - defines baseline behavior, exclusions, and normal telemetry for this hunt</span>${reasoningBtn}</div>
        ${normalItemsHTML}${normalAddHTML}
      </div>
    </div>
    <div class="card">
      <div class="card-head">
        <span class="card-title">⚠ What Suspicious Looks Like</span>
        <div class="obs-head-actions">
          <span class="chip chip-yellow" style="font-size:10px;">${d.suspicious.length} adversary pattern${d.suspicious.length !== 1 ? 's' : ''}</span>
          <button class="obs-edit-card-btn${editingSuspicious ? ' on' : ''}" onclick="toggleObserveCardEdit('${id}','suspicious')" title="${editingSuspicious ? 'Done editing' : 'Edit suspicious patterns'}">✎</button>
        </div>
      </div>
      <div class="card-body" style="padding:8px 14px;">
        <div class="section-agent-line" style="margin-bottom:8px;"><b>💡 Hypothesis Agent</b><span>What Suspicious Looks Like - defines adversary patterns, anomaly thresholds, and escalation cues</span>${reasoningBtn}</div>
        ${suspItemsHTML}${suspAddHTML}
      </div>
    </div>`;

  side.innerHTML = '';
}
