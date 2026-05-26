/* ── observe.js ───────────────────────────────────────────────────────────
   Hunt Observe stage functions. Loaded after app.js.
   ──────────────────────────────────────────────────────────────────────── */

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
      Network: ['JA3: 3b5074b1b5d032e5620f69f9159e9c4d (Cobalt Strike profile)', '185.220.101.47:443 and :8443', 'Beacon interval 60s ± 2s', 'Dual-port primary + fallback C2 channel'],
      Files: ['New scheduled tasks outside SCCM namespace', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MicrosoftEdgeUpdate', 'LSASS minidump in %TEMP% or C:\\ProgramData\\', 'Staging files in non-standard locations'],
      Authentication: ['Off-hours NTLM/Kerberos from CORP\\jsmith', 'Lateral auth via ADMIN$ across 14 hosts', 'TGS-REQ spike — 7 SPNs within 5 min (T1558.003)'],
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
          Files: ['lsass.dmp / sekurlsa.log artefact in %TEMP% or C:\\ProgramData\\', 'Mimikatz or reflective DLL in non-standard path'],
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
          { text: 'RC4 TGS-REQ spike above 15/hr from a single account outside the scheduled backup window — threshold set post-SPN-exclusion' },
          { text: 'TGS request for SPNs not in the 147-entry CMDB exclusion list from a non-service account — likely targeted enumeration' },
        ],
        observables: {
          'Key Events': ['EventCode 4769 · TicketEncryptionType=0x17 (RC4) · ServiceName ∉ 147-SPN exclusion list', 'EventCode 4768 burst — multiple Kerberos AS-REQ from single account in short window'],
          Account: ['CORP\\jsmith — 11 distinct SPN requests in 5 min including krbtgt (23:17 UTC)', 'SPNs targeted: krbtgt/CORP, MSSQLSvc/WIN-SQL02:1433, HTTP/intranet.corp.local'],
          'Detection Tuning': ['RC4 burst threshold: 15/hr · 147 CMDB SPN exclusions loaded (BackupExec + MSSQLSvc)', 'FP rate dropped from 22% (TH-2026-035) to <2% after exclusion list applied'],
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
          { text: 'JA3 fingerprint 3b5074b1b5d032e5620f69f9159e9c4d matching known Cobalt Strike malleable C2 profiles' },
          { text: 'Short-lived Let\'s Encrypt certificate (lifetime < 24hr) with non-browser or empty user-agent string to external IP' },
          { text: 'Outbound HTTPS to ASN associated with VPS/hosting infrastructure (Frantech, Mullvad, AS62160) with no prior baseline' },
          { text: 'Dual-port C2 channel: primary :443 + fallback :8443 to same destination IP with identical beacon timing' },
        ],
        observables: {
          Network: ['185.220.101.47:443 — JA3 3b5074b1b5d032e5620f69f9159e9c4d · beacon 60.1s ±0.3s stdev', '185.220.101.47:8443 — fallback C2 channel, identical JA3 + timing'],
          Certificate: ['CN=update.windows-cdn[.]net · Let\'s Encrypt · issued < 24hr · 1 SAN · not in approved cert baseline'],
          'Detection Path': ['JA3 fingerprint match (Zeek SSL log)', 'Beacon interval regularity: stdev < 5s over 30-min window', 'Short cert lifetime + non-browser UA string in HTTP log'],
          'Prior Hunt': ['TH-2025-091 — zero JA3 hits · net-new cert-chain path not previously hunted · Alice Chen flagged gap'],
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
      { text: 'CI/CD build artifacts signed by the corporate code-signing certificate — verified against artefact registry on publish' },
      { text: 'Scheduled build tasks created by the CI/CD service account (svc-build) from the approved build server only' },
      { text: 'DLL loads on downstream hosts matching the signed artefact registry hash list' },
      { text: 'Outbound HTTPS from SRV-BUILD01 to known package registries (npm, PyPI, Maven) during build windows' },
    ],
    suspicious: [
      { text: 'Unsigned binaries published to the artefact repository — does not match any registered build output hash' },
      { text: 'Scheduled task named svchost or similar system-sounding name created by the build service account' },
      { text: 'DLL load on downstream host not matching the signed artefact hash — potential sideload payload' },
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
  '038': {
    normal: [
      { text: 'DNS queries to corporate resolvers (10.0.0.1, 10.0.0.2) with normal subdomain depth (≤ 3 labels)' },
      { text: 'DNS TXT record queries for SPF/DKIM validation from mail servers — expected periodic pattern' },
      { text: 'Standard DNS query volumes: < 100 queries/min per host for workstations, < 1000/min for servers' },
      { text: 'Authorised monitoring tools making DNS queries with known process signatures (SIEM agents, MDR sensors)' },
    ],
    suspicious: [
      { text: 'High-entropy subdomain queries — random-looking labels > 20 chars suggest DNS tunnelling' },
      { text: 'DNS TXT record queries from non-mail processes — data exfil via TXT record payload' },
      { text: 'Query volume spike: > 500 queries/min per workstation or > 5000/min per server from single process' },
      { text: 'Large DNS response payloads (> 512 bytes) from external resolvers — potential C2 channel data delivery' },
      { text: 'DNS queries to newly registered or low-reputation domains with no prior baseline history' },
    ],
    observables: {
      Processes: ['Any process making high-volume DNS queries', 'Processes querying non-corporate resolvers', 'Dnscat2, iodine, or similar DNS tunnel tooling'],
      Network: ['High-entropy subdomains (e.g. a1b2c3.evil.com)', 'DNS TXT queries from non-mail processes', 'Large UDP/TCP DNS payloads > 512 bytes', 'Queries to newly registered domains (< 30 days)'],
      Files: ['DNS tunnel configuration files', 'Exfiltrated data encoded in DNS labels'],
      Authentication: ['N/A — DNS tunnelling typically bypasses auth layer'],
    }
  },
};

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
  const shId = (typeof activeSubhunt !== 'undefined' && activeSubhunt !== 'all') ? activeSubhunt : null;
  const shData = (shId && huntData.subhunts && huntData.subhunts[shId]) ? huntData.subhunts[shId] : null;
  const d = shData || huntData;

  // Subhunt context banner (shown when a specific subhunt is active)
  const subhuntBannerHTML = shData ? `
    <div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:rgba(59,130,246,.06);border:1px solid rgba(59,130,246,.2);border-radius:var(--radius-sm);margin-bottom:10px;">
      <span style="font-size:11px;color:var(--muted);">Observe profile for</span>
      <span class="chip ${shData.ttpChip}" style="font-size:10px;">${shData.label}</span>
    </div>` : '';

  const normalHTML = d.normal.map(n => `
    <div class="obs-item">
      <span class="obs-item-icon" style="color:var(--green);">✓</span>
      <span>${n.text}</span>
    </div>`).join('');
  const suspHTML = d.suspicious.map(s => `
    <div class="obs-item">
      <span class="obs-item-icon" style="color:var(--yellow);">⚠</span>
      <span>${s.text}</span>
    </div>`).join('');
  main.innerHTML = `
    ${subhuntBannerHTML}
    <div class="info-bar"><span class="ib-icon">ℹ️</span><span>The <b>Observe</b> stage defines your environment baseline for this hunt — what normal looks like, what adversary activity looks like, and what artefacts to watch for. This informs agent thresholds and exclusions applied in Learn and Check.</span></div>
    <div class="card">
      <div class="card-head">
        <span class="card-title">✅ What Normal Looks Like</span>
        <span class="chip chip-green" style="font-size:10px;">${d.normal.length} baseline patterns</span>
      </div>
      <div class="card-body" style="padding:8px 14px;">${normalHTML}</div>
    </div>
    <div class="card">
      <div class="card-head">
        <span class="card-title">⚠ What Suspicious Looks Like</span>
        <span class="chip chip-yellow" style="font-size:10px;">${d.suspicious.length} adversary patterns</span>
      </div>
      <div class="card-body" style="padding:8px 14px;">${suspHTML}</div>
    </div>`;
  const obsHTML = Object.entries(d.observables).map(([cat, items]) => `
    <div class="obs-cat-label">${cat}</div>
    ${items.map(item => `<div class="obs-observable">${item}</div>`).join('')}`).join('');

  const topoSVG = `<svg viewBox="0 0 260 220" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:auto;display:block;">
    <defs>
      <marker id="arr" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
        <path d="M0,0 L0,6 L6,3 z" fill="#263550"/>
      </marker>
    </defs>
    <!-- Lines from Orchestrator (130,110) to agents -->
    <line x1="130" y1="110" x2="50" y2="50"  stroke="#263550" stroke-width="1.5" class="topo-line" marker-end="url(#arr)"/>
    <line x1="130" y1="110" x2="210" y2="50" stroke="#263550" stroke-width="1.5" class="topo-line" marker-end="url(#arr)"/>
    <line x1="130" y1="110" x2="50" y2="175" stroke="#263550" stroke-width="1.5" class="topo-line" marker-end="url(#arr)"/>
    <line x1="130" y1="110" x2="210" y2="175"stroke="#263550" stroke-width="1.5" class="topo-line" marker-end="url(#arr)"/>
    <line x1="130" y1="110" x2="130" y2="185" stroke="#263550" stroke-width="1.5" class="topo-line" marker-end="url(#arr)"/>
    <!-- Orchestrator node (center) -->
    <circle cx="130" cy="110" r="22" fill="rgba(59,130,246,.15)" stroke="#3b82f6" stroke-width="2"/>
    <circle cx="130" cy="110" r="8" fill="#3b82f6" class="topo-pulse"/>
    <text x="130" y="141" text-anchor="middle" class="topo-label" fill="#94a3b8">Orchestrator</text>
    <!-- Hypothesis (top-left) -->
    <circle cx="50" cy="50" r="15" fill="rgba(20,184,166,.12)" stroke="#14b8a6" stroke-width="1.5"/>
    <text x="50" y="54" text-anchor="middle" style="font-size:13px;" fill="#14b8a6">💡</text>
    <text x="50" y="72" text-anchor="middle" class="topo-sub" fill="#4e6180">Hypothesis</text>
    <!-- Data Eng (top-right) -->
    <circle cx="210" cy="50" r="15" fill="rgba(99,102,241,.12)" stroke="#6366f1" stroke-width="1.5"/>
    <text x="210" y="54" text-anchor="middle" style="font-size:13px;" fill="#6366f1">🗄️</text>
    <text x="210" y="72" text-anchor="middle" class="topo-sub" fill="#4e6180">Data Eng</text>
    <!-- Tradecraft (bottom-left) -->
    <circle cx="50" cy="175" r="15" fill="rgba(245,158,11,.12)" stroke="#f59e0b" stroke-width="1.5"/>
    <text x="50" y="179" text-anchor="middle" style="font-size:13px;" fill="#f59e0b">🧠</text>
    <text x="50" y="197" text-anchor="middle" class="topo-sub" fill="#4e6180">Tradecraft</text>
    <!-- Detection (bottom-center) -->
    <circle cx="130" cy="185" r="15" fill="rgba(16,185,129,.12)" stroke="#10b981" stroke-width="1.5"/>
    <text x="130" y="189" text-anchor="middle" style="font-size:13px;" fill="#10b981">⚙️</text>
    <text x="130" y="207" text-anchor="middle" class="topo-sub" fill="#4e6180">Detection</text>
    <!-- Validation (bottom-right) -->
    <circle cx="210" cy="175" r="15" fill="rgba(139,92,246,.12)" stroke="#8b5cf6" stroke-width="1.5"/>
    <text x="210" y="179" text-anchor="middle" style="font-size:13px;" fill="#8b5cf6">✅</text>
    <text x="210" y="197" text-anchor="middle" class="topo-sub" fill="#4e6180">Validation</text>
  </svg>`;

  side.innerHTML = `
    <div class="card topo-card">
      <div class="card-head">
        <span class="card-title">🔗 Agent Topology</span>
        <span class="chip chip-blue" style="font-size:10px;">5 agents</span>
      </div>
      <div class="topo-svg-wrap">${topoSVG}</div>
    </div>
    <div class="card">
      <div class="card-head"><span class="card-title">🔭 Expected Observables</span></div>
      <div class="card-body" style="padding:8px 14px;">${obsHTML}</div>
    </div>`;
}

