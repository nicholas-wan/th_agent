/* ── Keep Stage ─────────────────────────────────────────────────────────
   Hunt data (keepData, huntNotes, findingComments), findings, timeline,
   TTP selector, gate log, velocity card, swimlane view, notes.
   Loaded after app.js — references globals declared there.
   ──────────────────────────────────────────────────────────────────────── */
// ── Keep tab — hunt data ──
const keepData = {
  '041': {
    title: 'TH-2026-041', label: 'Volt Typhoon · Active', labelClass: 'chip-red',
    createdBy: 'alice', createdAt: 'Apr 27, 2026 · 09:15',
    criticals: 3, highs: 9,
    findings: [
      { sev:'c', title:'LSASS Memory Access — Process Chain Anomaly',        meta:'WIN-DC01 · RAA Supervisor Agent · T1003.001 · 2m ago',   drawer:'tradecraft' },
      { sev:'c', title:'Lateral Movement via PsExec — 14 hosts',             meta:'10.0.0.0/8 · RAA Supervisor Agent · T1570 · 5m ago',      drawer:'tradecraft' },
      { sev:'c', title:'Cobalt Strike C2 Beacon — JA3 rule match',           meta:'185.220.101.47 · Detection Logic Agent · T1071.001 · 8m ago',    drawer:'detection'  },
      { sev:'h', title:'Kerberoasting — Cmd-line Anomaly, 7 SPNs',           meta:'corp.local · RAA Supervisor Agent · T1558.003 · 11m ago', drawer:'tradecraft' },
      { sev:'h', title:'Registry Run Key — Validated persistence rule',      meta:'SRV-APP03 · Rule Validation Agent · T1547.001 · 15m ago',        drawer:'validation' },
      { sev:'h', title:'DNS TXT Exfiltration Pattern',                       meta:'evilc2[.]net · Detection Logic Agent · T1041 · 19m ago',         drawer:'detection'  },
      { sev:'m', title:'PowerShell Encoded Command — Anomaly Score 81',      meta:'WIN-WS041 · RAA Supervisor Agent · T1059.001 · 22m ago',  drawer:'tradecraft' },
      { sev:'m', title:'Shadow Copy Deletion via vssadmin — Score 97',       meta:'WIN-DC01 · RAA Supervisor Agent · T1490 · 31m ago',       drawer:'tradecraft' },
    ],
    lock: {
      l: 'Ingested CISA AA24-038A (Volt Typhoon). Extracted 14 ATT&amp;CK techniques. Generated 4 hypotheses focused on lateral movement, credential dumping, Kerberoasting, and C2 beaconing.',
      o: 'H-01 confirmed (PsExec lateral movement — 14 hosts). H-02 confirmed (LSASS credential dump — WIN-DC01). H-03 likely (Kerberoasting). H-04 under investigation (Cobalt Strike C2 profile match).',
      c: 'SPL queries executed in Splunk ES via MCP. 14 hits on H-01 (index=windows). MITRE coverage: 4 confirmed, 3 partial. Detection rules generated and pushed to SIEM.',
      k: 'Recording in progress. 8 findings documented. Recommend IR escalation for WIN-DC01. New detection rules deployed.',
      kItalic: true,
      raa: { relevant: true, note: 'RAA triggered — 2 analytics, 62 hits confirmed (T1570, T1078.002)' },
    },
    timeline: [
      { color:'red',    text:'<b>RAA Supervisor Agent</b> — process chain anomaly, LSASS access flagged CRITICAL', time:'09:41', tag:'T1003.001', host:'WIN-DC01'  },
      { color:'blue',   text:'<b>RAA Supervisor Agent</b> — PsExec process chain confirmed, 14 hosts',            time:'09:38', tag:'T1570',     host:'CORP NET'  },
      { color:'orange', text:'<b>Detection Logic Agent</b> — C2 beacon rule matched, JA3 hit on 185.220.101.47',  time:'09:35', tag:'T1071.001', host:'EXT'       },
      { color:'yellow', text:'<b>RAA Supervisor Agent</b> — cmd-line anomaly, Kerberoasting pattern (7 SPNs)',    time:'09:32', tag:'T1558.003', host:'WIN-WS041' },
      { color:'indigo', text:'<b>Rule Validation Agent</b> — persistence rule triggered, svcupd.exe registry key',time:'09:29', tag:'T1547.001', host:'SRV-APP03' },
      { color:'green',  text:'<b>Detection Logic Agent</b> — SPL rules validated and pushed to SIEM',             time:'09:18', tag:'',          host:'SYSTEM'    },
      { color:'blue',   text:'<b>Orchestrator Agent</b> — Hunt TH-2026-041 started, 6 agents deployed',          time:'09:15', tag:'',          host:'SYSTEM'    },
      { color:'teal',   text:'<b>Hypothesis Agent</b> — 4 hypotheses generated from 14 TTPs · 3 past hunts recalled · coverage gaps flagged', time:'09:14', tag:'', host:'SYSTEM' },
    ],
    report: {
      status: 'Active', statusClass: 'chip-red',
      summary: 'This hunt targeted active APT29/Volt Typhoon intrusion activity across the corporate Windows domain. Over a 26-minute window, agents analysed authentication logs, Sysmon process telemetry, and network flow data against four hypotheses derived from the CISA AA24-038A advisory. All four hypotheses returned positive results, confirming a live, multi-stage intrusion involving lateral movement, credential dumping, Kerberoasting, and an active C2 channel.',
      approach: 'H-01 (PsExec lateral movement) was confirmed first via off-hours authentication analysis — 14 distinct hosts were touched by a single compromised account (CORP\\jsmith) in two sessions, far exceeding the 3-host detection threshold. H-02 (LSASS credential dump) was confirmed via process chain anomaly: <span class="report-ioc">rundll32.exe</span> accessed LSASS with handle <span class="report-ioc">0x1fffff</span> from an <span class="report-ioc">explorer.exe</span> parent on WIN-DC01, consistent with Mimikatz sekurlsa::logonpasswords. H-03 (Kerberoasting) was confirmed by RC4 TGS-REQ volume analysis — jsmith requested 11 unique SPNs in a 5-minute window against the CORP domain. H-04 (C2 beacon) was confirmed by JA3 fingerprint match — beacon interval 60.1s, watermark <span class="report-ioc">0x4e4b5547</span>, destination <span class="report-ioc">185.220.101.47:443</span>.',
      impact: [
        { val:'14', lbl:'Hosts involved', color:'var(--red)' },
        { val:'26m', lbl:'Detection to containment', color:'var(--text)' },
        { val:'3', lbl:'Critical findings', color:'var(--red)' },
        { val:'4', lbl:'Rules deployed', color:'var(--green)' },
      ],
      recommendations: [
        'Escalate to Incident Response immediately — isolate WIN-DC01 and acquire memory image before reboot.',
        'Suspend CORP\\jsmith and rotate all credentials authenticated from that account in the past 72 hours.',
        'Push perimeter block for <span class="report-ioc">185.220.101.47/32</span> and audit all outbound connections on port 443 for matching JA3 hashes.',
        'Review CORP\\svc-sql01 and CORP\\admin-backup for signs of credential reuse — both accounts exceeded the lateral movement threshold.',
        'Schedule full EDR coverage audit — WIN-DC01 LSASS access was detected via RAA, not a deployed rule.',
      ]
    },
    graph: {
      nodes: [
        { id:'jsmith',  label:'CORP\\\\jsmith',       shape:'ellipse', cls:'gn-user',    cx:130, cy:110 },
        { id:'ws089',   label:'WS-089',               shape:'rect',    cls:'gn-host',   cx:40,  cy:40  },
        { id:'windc01', label:'WIN-DC01 (T0)',         shape:'rect',    cls:'gn-tier0',  cx:220, cy:40  },
        { id:'winsql',  label:'WIN-SQL02',             shape:'rect',    cls:'gn-host',   cx:220, cy:110 },
        { id:'winfs01', label:'WIN-FS01',              shape:'rect',    cls:'gn-host',   cx:220, cy:180 },
        { id:'rundll',  label:'rundll32.exe',          shape:'rect',    cls:'gn-malware',cx:130, cy:200 },
      ],
      edges: [
        { from:'ws089',  to:'jsmith',  label:'source host',    cls:'ge-normal'   },
        { from:'jsmith', to:'windc01', label:'T1570 pivot',     cls:'ge-critical' },
        { from:'jsmith', to:'winsql',  label:'T1570 pivot',     cls:'ge-critical' },
        { from:'jsmith', to:'winfs01', label:'T1570 pivot',     cls:'ge-critical' },
        { from:'rundll', to:'windc01', label:'T1003.001 0x1fffff', cls:'ge-critical' },
      ]
    },
    pivot: {
      huntId: 'TH-2026-042',
      hypothesis: 'CORP\\jsmith lateral movement confirms a compromised domain account with DC access. Pivot to a privileged account abuse hunt: enumerate all accounts that authenticated from WIN-DC01 in the 72h prior to detection, cross-referenced against AD for unusual delegation assignments or newly registered SPNs consistent with DCSync staging.',
      techniques: ['T1078.002','T1484.001','T1003.006'],
      rationale: 'The attacker reached WIN-DC01 — if DCSync or Golden Ticket generation occurred, credential rotation alone is insufficient. A follow-on hunt seeded with the confirmed jsmith pivot chain and DC auth logs closes this gap before IR hand-off.',
      seedData: ['CORP\\jsmith session log (72h)', 'WIN-DC01 EventCode 4672/4768 auth events', 'AD delegation & SPN change audit log']
    }
  },
  '040': {
    title: 'TH-2026-040', label: 'FIN7 Ransomware · Closed', labelClass: 'chip-yellow',
    createdBy: 'marcus', createdAt: 'Apr 24, 2026 · 13:15',
    criticals: 2, highs: 6,
    findings: [
      { sev:'c', title:'Ransomware Pre-deployment — Shadow Copy Deletion', meta:'WIN-FS02 · RAA Supervisor Agent · T1490 · 3d ago',        drawer:'tradecraft' },
      { sev:'c', title:'Phishing Payload Execution — Office Macro',        meta:'WIN-WS012 · Detection Logic Agent · T1204 · 3d ago',             drawer:'detection'  },
      { sev:'h', title:'DLL Sideloading — DISM.exe',                       meta:'WIN-WS012 · Rule Validation Agent · T1574.002 · 3d ago',         drawer:'validation' },
      { sev:'h', title:'Data Encrypted for Impact',                        meta:'WIN-FS02 · RAA Supervisor Agent · T1486 · 3d ago',         drawer:'tradecraft' },
      { sev:'h', title:'Credential Access via LSASS Dump',                 meta:'WIN-DC02 · Detection Logic Agent · T1003.001 · 3d ago',           drawer:'detection'  },
      { sev:'m', title:'Phishing Email — Malicious Attachment Opened',     meta:'mail.corp.local · Detection Logic Agent · T1566.001 · 3d ago',   drawer:'detection'  },
    ],
    lock: {
      l: 'Ingested FS-ISAC TLP:AMBER report on FIN7 ransomware TTPs. Extracted 9 ATT&amp;CK techniques. 2 hypotheses generated: phishing delivery and pre-ransomware staging.',
      o: 'H-01 confirmed (phishing macro delivery to 3 hosts). H-02 confirmed (ransomware staging — shadow copy deletion on FS02).',
      c: 'SPL queries executed in Splunk ES. 8 hits on H-01 (index=security). MITRE coverage: 6 confirmed.',
      k: 'Hunt closed. 6 findings documented. FS02 isolated. 5 new detection rules deployed to SIEM.',
      kItalic: false,
      raa: { relevant: true, note: 'RAA triggered — Process Chain Anomaly, 12 hits (T1204 macro chain, T1490 shadow copy deletion)' },
    },
    timeline: [
      { color:'red',    text:'<b>RAA Supervisor Agent</b> — shadow copy deletion detected, ransomware staging confirmed', time:'14:22', tag:'T1490',     host:'WIN-FS02'  },
      { color:'red',    text:'<b>Detection Logic Agent</b> — data encryption pattern detected on FS02',                   time:'14:19', tag:'T1486',     host:'WIN-FS02'  },
      { color:'orange', text:'<b>Rule Validation Agent</b> — DLL sideloading rule matched DISM.exe',                      time:'14:05', tag:'T1574.002', host:'WIN-WS012' },
      { color:'yellow', text:'<b>Detection Logic Agent</b> — Office macro execution flagged on WIN-WS012',                time:'13:47', tag:'T1204',     host:'WIN-WS012' },
      { color:'blue',   text:'<b>RAA Supervisor Agent</b> — phishing email linked to FIN7 campaign',                     time:'13:30', tag:'T1566.001', host:'EXT'       },
      { color:'green',  text:'<b>Orchestrator Agent</b> — Hunt TH-2026-040 started, 5 agents deployed',                  time:'13:15', tag:'',          host:'SYSTEM'    },
    ],
    report: {
      status: 'Closed', statusClass: 'chip-green',
      summary: 'This hunt investigated FIN7 ransomware precursor activity in the Finance segment following a FS-ISAC TLP:AMBER advisory. Agents identified a complete pre-ransomware kill chain over a 2-hour 14-minute engagement: phishing delivery via Office macro, DLL sideloading for persistence, credential access via LSASS dump, and ransomware staging confirmed by shadow copy deletion on the primary payroll file server (WIN-FS02). Payroll data was partially encrypted before automated EDR containment triggered.',
      approach: 'H-01 (phishing delivery) was confirmed via <span class="report-ioc">T1204</span> — Office macro execution flagged on WIN-WS012 linked to a TA577-attributed phishing campaign. H-02 (ransomware staging) was confirmed via <span class="report-ioc">T1490</span> — <span class="report-ioc">vssadmin delete shadows /all</span> detected on WIN-FS02 with a command-line anomaly score of 97. DLL sideloading via <span class="report-ioc">DISM.exe</span> was identified as the persistence mechanism between initial access and the ransomware deployment stage.',
      impact: [
        { val:'2h 14m', lbl:'Hunt duration', color:'var(--text)' },
        { val:'6', lbl:'Findings', color:'var(--yellow)' },
        { val:'1', lbl:'Server isolated', color:'var(--red)' },
        { val:'5', lbl:'Rules deployed', color:'var(--green)' },
      ],
      recommendations: [
        'Restore WIN-FS02 payroll data from Apr 23 backup — coordinate with IT and Payroll team on timeline.',
        'Re-image WIN-WS012; treat all credentials cached on that host as compromised.',
        'Submit IOC package (file hashes, C2 domains) to FS-ISAC and notify sector peers via TLP:AMBER channel.',
        'Audit Office macro policy — enforce signed-macro-only policy across Finance segment endpoints.',
        'Deploy DLL sideloading detection rule to all hosts; current rule was Finance-scoped only.',
      ]
    },
    graph: {
      nodes: [
        { id:'email',   label:'Phishing Email',     shape:'ellipse', cls:'gn-user',    cx:50,  cy:100 },
        { id:'ws012',   label:'WIN-WS012',           shape:'rect',    cls:'gn-host',   cx:160, cy:40  },
        { id:'dism',    label:'DISM.exe (sideload)', shape:'rect',    cls:'gn-malware',cx:160, cy:110 },
        { id:'winfs02', label:'WIN-FS02 (payroll)',  shape:'rect',    cls:'gn-tier0',  cx:160, cy:180 },
        { id:'windc02', label:'WIN-DC02',            shape:'rect',    cls:'gn-host',   cx:270, cy:110 },
      ],
      edges: [
        { from:'email',  to:'ws012',   label:'T1566.001 macro',   cls:'ge-critical' },
        { from:'ws012',  to:'dism',    label:'T1574.002 sideload',cls:'ge-critical' },
        { from:'dism',   to:'windc02', label:'T1003.001 LSASS',   cls:'ge-critical' },
        { from:'dism',   to:'winfs02', label:'T1490 vssadmin',    cls:'ge-critical' },
      ]
    },
    pivot: {
      huntId: 'TH-2026-041-F',
      hypothesis: 'FIN7 phishing delivered via WIN-WS012. Pivot to a credential reuse hunt across the Finance segment: trace all NTLM pass-the-hash authentications originating from WIN-WS012 in the 48h post-infection window, looking for lateral spread to adjacent finance servers before the host was re-imaged.',
      techniques: ['T1021.002','T1550.002','T1003.001'],
      rationale: 'Re-imaging WIN-WS012 and isolating FS02 removes the active threat, but the credential reuse window is still open. Any Finance server touched with stolen credentials in that 48h window is an unverified risk — this hunt closes it before the next patch cycle.',
      seedData: ['WIN-WS012 NTLM auth log (48h post-infection)', 'Finance segment host list from CMDB', 'LSASS dump artefact hashes (T1003.001 finding)']
    }
  },
  '039': {
    title: 'TH-2026-039', label: 'Supply Chain · Closed', labelClass: 'chip-gray',
    createdBy: 'priya', createdAt: 'Apr 14, 2026 · 10:15',
    criticals: 1, highs: 4,
    findings: [
      { sev:'c', title:'Trojanised Build Tool — Supply Chain Compromise',  meta:'build-srv01 · Detection Logic Agent · T1195.002 · 2w ago',            drawer:'detection'  },
      { sev:'h', title:'DLL Sideloading via Legitimate Binary',            meta:'10 hosts · Rule Validation Agent · T1574.002 · 2w ago',               drawer:'validation' },
      { sev:'h', title:'C2 Beacon — Cobalt Strike over HTTPS',             meta:'update.cdn-cache[.]net · Detection Logic Agent · T1071.001 · 2w ago', drawer:'detection'  },
      { sev:'h', title:'Scheduled Task Persistence — svchost wrapper',     meta:'SRV-BUILD01 · RAA Supervisor Agent · T1053.005 · 2w ago',      drawer:'tradecraft' },
      { sev:'m', title:'Exfiltration over C2 Channel',                     meta:'update.cdn-cache[.]net · Detection Logic Agent · T1041 · 2w ago',     drawer:'detection'  },
    ],
    lock: {
      l: 'Ingested CISA supply chain advisory (SolarWinds-pattern). Extracted 7 ATT&amp;CK techniques. 2 hypotheses generated: trojanised build artifacts and C2 staging.',
      o: 'H-01 confirmed (trojanised build tool on SRV-BUILD01). H-02 confirmed (Cobalt Strike C2 via HTTPS).',
      c: 'SPL queries executed in Splunk ES. 6 hits on H-01 (index=windows/sysmon). MITRE coverage: 5 confirmed.',
      k: 'Hunt closed. 5 findings documented. SRV-BUILD01 re-imaged. 4 new detection rules deployed.',
      kItalic: false,
      raa: { relevant: true, partial: true, note: 'RAA partial — Process Chain triggered (8 hits, T1574.002). T1071.001 deferred to SPL (network-layer; outside RAA scope)' },
    },
    timeline: [
      { color:'red',    text:'<b>Detection Logic Agent</b> — trojanised build artifact confirmed on SRV-BUILD01',  time:'11:03', tag:'T1195.002' },
      { color:'orange', text:'<b>Detection Logic Agent</b> — C2 beacon over HTTPS, JA3 match',                     time:'10:52', tag:'T1071.001' },
      { color:'indigo', text:'<b>Rule Validation Agent</b> — DLL sideloading confirmed on 10 hosts',               time:'10:44', tag:'T1574.002' },
      { color:'yellow', text:'<b>RAA Supervisor Agent</b> — scheduled task persistence detected',                  time:'10:38', tag:'T1053.005' },
      { color:'blue',   text:'<b>Orchestrator Agent</b> — Hunt TH-2026-039 started, 5 agents deployed',            time:'10:15', tag:''          },
    ],
    report: {
      status: 'Closed', statusClass: 'chip-green',
      summary: 'This hunt investigated supply chain compromise indicators following a CISA advisory on SolarWinds-pattern intrusions. Over a 48-minute engagement, agents confirmed that the primary CI/CD build server (SRV-BUILD01) had been serving trojanised build artifacts for a four-day window (Apr 10–14). All build outputs from that window are considered potentially compromised. A Cobalt Strike C2 channel was simultaneously active, suggesting the implant was already staging for lateral movement at the time of detection.',
      approach: 'H-01 (trojanised build artifact) was confirmed by cross-referencing Sysmon file-creation events on SRV-BUILD01 with known-good binary hashes from the artefact registry — an unsigned binary introduced on Apr 10 did not match any registered build output. H-02 (C2 staging) was confirmed via JA3 fingerprint on outbound HTTPS from SRV-BUILD01 to <span class="report-ioc">update.cdn-cache[.]net</span>, matching a Cobalt Strike malleable profile. DLL sideloading via a legitimate Windows binary was identified on 10 downstream hosts that had pulled the affected build.',
      impact: [
        { val:'10', lbl:'Hosts exposed', color:'var(--yellow)' },
        { val:'4d', lbl:'Dwell time', color:'var(--red)' },
        { val:'5', lbl:'Findings', color:'var(--text)' },
        { val:'4', lbl:'Rules deployed', color:'var(--green)' },
      ],
      recommendations: [
        'Re-image SRV-BUILD01 and restore from a pre-Apr 10 snapshot verified against known-good hashes.',
        'Invalidate and re-sign all build artifacts produced between Apr 10–14; redistribute to affected hosts before next deployment window.',
        'Audit the 10 hosts that pulled the affected build — treat as potentially implanted; prioritise EDR sweep.',
        'Block <span class="report-ioc">update.cdn-cache[.]net</span> at perimeter DNS and proxy; check for any other outbound connections to that domain.',
        'Harden CI/CD pipeline: enforce binary signing verification as a required build gate before artifact publication.',
      ]
    },
    pivot: {
      huntId: 'TH-2026-040-SC',
      hypothesis: 'SRV-BUILD01 served trojanised artifacts for 4 days. Pivot to a blast-radius containment hunt: query all 10 downstream hosts for the svchost-wrapper scheduled task and any unsigned DLLs loaded since Apr 10, to confirm whether any host is still beaconing or has staged additional payloads.',
      techniques: ['T1053.005','T1574.002','T1041'],
      rationale: 'Re-imaging SRV-BUILD01 removes the source, not the payload. Each of the 10 downstream hosts remains unverified — any one could still be an active beacon. This hunt must complete before the next deployment window opens to prevent reinfection via a still-compromised host.',
      seedData: ['Affected downstream host list (10 hosts)', 'Apr 10–14 artifact hash inventory from artefact registry', 'Sysmon DLL load events (index=sysmon EventCode=7) since Apr 10']
    }
  }
};

// per-hunt notes store (pre-populated with demo notes)
const huntNotes = {
  '041': [
    { text: 'jsmith account suspended. Confirmed lateral movement from WS-089 to WIN-DC01. Escalated to IR team at 14:30 — recommend memory acquisition on WIN-DC01 before reboot.', ts: '09:47 · Apr 27', id: 1001, author: 'marcus' },
    { text: 'JA3 hash 3b5074b1b5d032e5620f69f9159e9c4d cross-referenced with CTI — confirmed Cobalt Strike malleable C2 profile (watermark 0x4e4b5547). Firewall block pushed to perimeter for 185.220.101.47/32.', ts: '09:43 · Apr 27', id: 1002, author: 'alice' },
  ],
  '040': [
    { text: 'FIN7 TTP cluster confirmed via CTI correlation (FIN7 2024 cluster, TA577). IOC package submitted to FS-ISAC. Hunt closure report filed in ServiceNow #INC-2040882.', ts: '14:35 · Apr 24', id: 1003, author: 'ryan' },
    { text: 'FS02 payroll data confirmed encrypted. Ransom note at C:\\Recovery\\README.txt. IT restoring from Apr 23 backup — ETA 4h. Payroll team notified of potential delay.', ts: '14:28 · Apr 24', id: 1004, author: 'priya' },
  ],
  '039': [
    { text: 'SRV-BUILD01 re-image complete. All build artifacts from Apr 10–14 flagged as potentially compromised. DevOps notified — re-sign and re-distribute affected packages before next deployment window.', ts: '11:22 · Apr 14', id: 1005, author: 'alice' },
  ],
  // ── Past hunt notes — referenced by Learn stage for institutional memory ──
  '038': [
    { text: 'jsmith service account was the pivot point — PsExec confirmed from WS-089 to 7 additional hosts via ADMIN$ share. Lowered detection rule threshold to single hop to cut dwell time. Pre-load this threshold for any follow-on Volt Typhoon hunt.', ts: '16:21 · Feb 14', id: 2001, author: 'marcus' },
    { text: 'WMI process creation from svchost caught via Sysmon EventCode 1. Parent chain: svchost → wmiprvse → cmd.exe — outside baseline for this host class. Added as secondary indicator to detection pack. Cross-check this chain in any follow-on Volt Typhoon hypothesis.', ts: '15:48 · Feb 14', id: 2002, author: 'alice' },
    { text: 'Off-hours logon rule had 12% FP rate from overnight batch jobs on DB-SRV-02 and DB-SRV-03. Added time-boxed exclusion for 02:00–04:00 UTC on those hosts — FP rate now at 1.2%. Apply exclusion in future runs.', ts: '15:30 · Feb 14', id: 2003, author: 'priya' },
  ],
  '035': [
    { text: 'Kerberoasting rule generating FPs for BackupExec and MSSQLSvc SPNs from the backup service. Added exclusion regex for known-good SPNs from CMDB — FP rate dropped from 22% to under 2%. Load SPN exclusion list into Detection Logic Agent before generating new Kerberoasting rules.', ts: '10:47 · Jan 08', id: 2004, author: 'marcus' },
    { text: 'LSASS accessed by rundll32.exe (PID 4812) spawned from explorer.exe — not a known AV or EDR process. Confirmed credential harvesting; memory acquisition sent to forensics. Future LSASS rules should specifically flag non-system parent processes.', ts: '11:05 · Jan 08', id: 2005, author: 'alice' },
    { text: 'WIN-DC01 and WIN-DC03 confirmed compromised. Recommend scoping any follow-on credential hunt to exclude known-good SPNs from CMDB and pre-filter BackupExec service accounts before running Kerberoasting queries.', ts: '10:30 · Jan 08', id: 2006, author: 'ryan' },
  ],
  '091': [
    { text: 'Scheduled task FPs came from SCCM deployments — tasks matching ConfigMgr_* pattern. Added exclusion regex to the rule. Any future scheduled task detection must pre-load this exclusion or it will generate significant noise in this environment.', ts: '14:10 · Nov 22', id: 2007, author: 'alice' },
    { text: 'Attacker used registry run key named MicrosoftEdgeUpdate to blend in with legitimate software. SIEM rule missed it — added binary signing cert validation. Future run key rules should verify cert chain, not just key name.', ts: '13:52 · Nov 22', id: 2008, author: 'marcus' },
  ],
};
let activeKeepHunt = '041';
let activeKeepTTP   = 'all';
let activeTimelineView = 'list';

function toggleCollapse(cardId, e) {
  if (e) e.stopPropagation();
  const card = document.getElementById(cardId);
  if (!card) return;
  card.classList.toggle('card-collapsed');
  const btn = card.querySelector('.collapse-btn');
  if (btn) btn.textContent = '▾'; // CSS rotation handles visual; text stays same
}

function switchKeepHunt(id) {
  activeKeepHunt = id;
  const hasData = !!keepData[id];

  // Dim the Keep sub-tab for hunts with no Keep data (drafts / unsupported hunts)
  const keepTab = document.getElementById('subtab-keep');
  if (keepTab) {
    keepTab.style.opacity = hasData ? '' : '0.38';
    keepTab.style.pointerEvents = hasData ? '' : 'none';
    keepTab.title = hasData ? '' : 'Keep stage not yet available for this hunt';
  }

  if (!hasData) {
    // Show a clear placeholder instead of stale content
    const el = document.getElementById('keep-hunt-creator');
    if (el) el.innerHTML = '';
    document.getElementById('keep-lock-chip').textContent = 'TH-2026-' + id;
    const statusEl = document.getElementById('keep-lock-status');
    if (statusEl) { statusEl.textContent = 'Draft'; statusEl.className = 'chip chip-gray'; }
    document.getElementById('keep-lock-body').innerHTML = `
      <div class="lock-4col-cell" style="grid-column:1/-1;padding:20px 18px;">
        <div style="font-size:12px;color:var(--muted);text-align:center;">
          📋 Keep stage not available — this hunt is still in <b style="color:var(--text);">Draft</b>.<br>
          <span style="font-size:11px;">Complete Learn, Observe and Check before a LOCK record can be filed.</span>
        </div>
      </div>`;
    document.getElementById('keep-findings-list').innerHTML = '';
    document.getElementById('keep-crit-chip').textContent = '—';
    document.getElementById('keep-high-chip').textContent = '—';
    document.getElementById('report-doc-body').innerHTML =
      '<div style="padding:20px;font-size:12px;color:var(--muted);text-align:center;">No report — hunt is Draft.</div>';
    const chip = document.getElementById('report-status-chip');
    if (chip) { chip.textContent = 'Draft'; chip.className = 'chip chip-gray'; }
    return;
  }

  renderKeepHunt(id);
  renderHuntReport(id);
  renderHuntPivot(id);
  renderSimilarHunts(id);
  // Always show the Hunt Report expanded when switching hunts so updated content is visible
  const reportCard = document.getElementById('card-report');
  if (reportCard) reportCard.classList.remove('card-collapsed');
  // Scroll Keep pane back to top so LOCK Record is visible first
  const keepPane = document.getElementById('subpane-keep');
  if (keepPane) keepPane.scrollTop = 0;
}

/* ── extract TTP id from a finding's meta string ── */
function extractTTP(meta) {
  return (meta.match(/T\d{4}(?:\.\d{3})?/) || [''])[0];
}

/* ── short display name for a TTP id ── */
function ttpShortName(id) {
  const full = ttpInfo[id]?.name || '';
  // Use text after last colon if present, otherwise full name, truncated to 18 chars
  const short = full.includes(':') ? full.split(':').pop().trim() : full;
  return short.length > 18 ? short.slice(0, 17) + '…' : short;
}

function renderKeepHunt(id) {
  const d = keepData[id];
  if (!d) return;
  // Reset TTP filter when switching hunts
  activeKeepTTP = 'all';

  // Creator strip
  const creator = users[d.createdBy];
  const creatorEl = document.getElementById('keep-hunt-creator');
  if (creatorEl && creator) {
    creatorEl.innerHTML = `${avatarHTML(d.createdBy)}<span>Hunt started by <b>${creator.name}</b></span><span style="color:var(--border2);">·</span><span>${creator.role}</span><span style="color:var(--border2);">·</span><span>${d.createdAt}</span>`;
  }

  // LOCK chip + 4-col body
  document.getElementById('keep-lock-chip').textContent = d.title;
  const statusEl = document.getElementById('keep-lock-status');
  if (statusEl) {
    statusEl.textContent = d.labelClass === 'chip-red' ? 'Active' : 'Closed';
    statusEl.className = 'chip ' + (d.labelClass === 'chip-red' ? 'chip-red' : 'chip-gray');
  }
  const lock = d.lock;
  document.getElementById('keep-lock-body').innerHTML = `
    <div class="lock-4col-cell">
      <div class="lock-cell-head"><span class="lock-letter lock-l">L</span><span class="lock-cell-label">Learn</span></div>
      <div class="lock-cell-text">${lock.l}</div>
    </div>
    <div class="lock-4col-cell">
      <div class="lock-cell-head"><span class="lock-letter lock-o">O</span><span class="lock-cell-label">Observe</span></div>
      <div class="lock-cell-text">${lock.o}</div>
    </div>
    <div class="lock-4col-cell">
      <div class="lock-cell-head"><span class="lock-letter lock-c">C</span><span class="lock-cell-label">Check</span></div>
      <div class="lock-cell-text">${lock.c}</div>
    </div>
    <div class="lock-4col-cell">
      <div class="lock-cell-head"><span class="lock-letter lock-k">K</span><span class="lock-cell-label">Keep</span></div>
      <div class="lock-cell-text"${lock.kItalic?' style="font-style:italic;"':''}>${lock.k}</div>
    </div>`;

  // Build TTP selector then render filtered views
  renderTTPSelector(d);
  renderKeepFindings(d);
  renderKeepTimeline(d);
  renderGateDecisionLog(id);
  renderEvidenceGraph(d);

  // Similar hunts summary
  const ss = document.getElementById('simhunts-summary');
  if (ss) ss.textContent = document.getElementById('sim-hunt-count')?.textContent || '';

  // Refresh notes
  renderNotes();
}

function renderEvidenceGraph(d) {
  const wrap = document.getElementById('keep-evidence-graph');
  const card = document.getElementById('card-evidence-graph');
  const chip = document.getElementById('evg-node-chip');
  if (!wrap) return;

  if (!d.graph) {
    if (card) card.style.display = 'none';
    return;
  }
  if (card) card.style.display = '';

  const { nodes, edges } = d.graph;
  if (chip) chip.textContent = nodes.length + ' nodes · ' + edges.length + ' edges';

  // Compute SVG bounds from node positions
  const pad = 40;
  const maxX = Math.max(...nodes.map(n => n.cx)) + pad + 50;
  const maxY = Math.max(...nodes.map(n => n.cy)) + pad + 20;

  // Arrow markers
  const defs = `<defs>
    <marker id="ge-arr-n" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L0,7 L7,3.5 z" fill="#263550"/></marker>
    <marker id="ge-arr-c" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L0,7 L7,3.5 z" fill="#ef4444" opacity=".7"/></marker>
  </defs>`;

  // Render edges
  function nodeCenter(id) {
    return nodes.find(n => n.id === id) || { cx:0, cy:0 };
  }
  const edgeSvg = edges.map(e => {
    const f = nodeCenter(e.from); const t = nodeCenter(e.to);
    // Shorten line by 18px each end so it doesn't overlap node
    const dx = t.cx - f.cx; const dy = t.cy - f.cy;
    const len = Math.sqrt(dx*dx + dy*dy) || 1;
    const ux = dx/len; const uy = dy/len;
    const x1 = f.cx + ux*18; const y1 = f.cy + uy*18;
    const x2 = t.cx - ux*22; const y2 = t.cy - uy*22;
    const mx = (x1+x2)/2; const my = (y1+y2)/2 - 10;
    return `<line class="${e.cls}" x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}" marker-end="url(#ge-arr-${e.cls==='ge-critical'?'c':'n'})"/>
            <text x="${mx.toFixed(1)}" y="${my.toFixed(1)}" text-anchor="middle" fill="#4e6180" style="font-size:8px;pointer-events:none;">${e.label}</text>`;
  }).join('');

  // Render nodes
  const nodeSvg = nodes.map(n => {
    const lw = n.label.length * 5.5 + 16;
    const lh = 22;
    if (n.shape === 'ellipse') {
      return `<g style="cursor:default;">
        <ellipse class="${n.cls}" cx="${n.cx}" cy="${n.cy}" rx="${lw/2}" ry="${lh/2}"/>
        <text x="${n.cx}" y="${n.cy+4}" text-anchor="middle" fill="#e2e8f0" style="font-size:9px;font-weight:600;pointer-events:none;">${n.label}</text>
      </g>`;
    }
    return `<g style="cursor:default;">
      <rect class="${n.cls}" x="${n.cx - lw/2}" y="${n.cy - lh/2}" width="${lw}" height="${lh}" rx="4"/>
      <text x="${n.cx}" y="${n.cy+4}" text-anchor="middle" fill="#e2e8f0" style="font-size:9px;font-weight:600;pointer-events:none;">${n.label}</text>
    </g>`;
  }).join('');

  wrap.innerHTML = `<svg class="ev-graph-svg" viewBox="0 0 ${maxX} ${maxY}" xmlns="http://www.w3.org/2000/svg">${defs}${edgeSvg}${nodeSvg}</svg>`;
}

function renderGateDecisionLog(huntId) {
  const el = document.getElementById('gdl-body');
  const chip = document.getElementById('gdl-count-chip');
  const summary = document.getElementById('gdl-summary');
  if (!el) return;
  const shortId = huntId.replace('TH-2026-','');
  const entries = gateDecisionLog[shortId] || [];
  if (chip) chip.textContent = entries.length + ' decision' + (entries.length !== 1 ? 's' : '');
  const mods = entries.filter(e => e.decision === 'modified').length;
  if (summary) summary.textContent = mods ? mods + ' modified' : entries.length ? 'all approved' : '';

  const agentColors = { orchestrator:'var(--blue)', hypothesis:'var(--teal)', tradecraft:'var(--yellow)',
    dataeng:'var(--indigo)', detection:'var(--green)' };
  const agentIcons  = { orchestrator:'🎛️', hypothesis:'💡', tradecraft:'🧠', dataeng:'🗄️', detection:'⚙️' };
  const decLabel = { approved:'✓ Approved', modified:'✏️ Modified', rejected:'✗ Rejected' };

  if (!entries.length) {
    el.innerHTML = '<div style="font-size:11px;color:var(--muted);padding:10px 0;text-align:center;">No gate decisions recorded for this hunt.</div>';
    return;
  }

  el.innerHTML = entries.map((e, i) => {
    const clr    = agentColors[e.agent] || 'var(--sub)';
    const icon   = agentIcons[e.agent] || '·';
    const decCls = 'gdl-dec gdl-dec-' + e.decision;
    const u      = users[e.analyst] || { initials:'?', bg:'rgba(100,116,139,.2)', color:'var(--sub)' };
    return `<div class="gdl-entry">
      <div class="gdl-spine">
        <div class="gdl-gate-num" style="background:${clr}18;color:${clr};">G${e.gate}</div>
        ${i < entries.length - 1 ? '<div class="gdl-connector"></div>' : ''}
      </div>
      <div class="gdl-body">
        <div class="gdl-top">
          <span style="font-size:12px;">${icon}</span>
          <span class="gdl-gate-name">${e.name}</span>
          <span class="${decCls}">${decLabel[e.decision]}</span>
          <div class="gdl-who">
            <div class="user-av" style="width:16px;height:16px;font-size:7px;background:${u.bg};color:${u.color};">${u.initials}</div>
            <span>${e.analyst} · ${e.ts}</span>
          </div>
        </div>
        ${e.original ? `<div style="font-size:10px;color:var(--muted);margin-bottom:3px;">Original: <span style="color:var(--sub);">${e.original}</span></div>` : ''}
        ${e.change ? `<div class="gdl-change"><b>Change:</b> ${e.change}</div>` : ''}
        ${e.reason ? `<div class="gdl-reason">💬 "${e.reason}"</div>` : ''}
      </div>
    </div>`;
  }).join('');
}


function renderTTPSelector(d) {
  const card = document.getElementById('keep-ttp-card');
  const pillsEl = document.getElementById('keep-ttp-pills');
  if (!card || !pillsEl) return;

  // Gather unique TTPs from findings, preserving order of first appearance
  const seen = new Map(); // ttpId -> { count, worstSev }
  const sevRank = { c:3, h:2, m:1 };
  d.findings.forEach(f => {
    const id = extractTTP(f.meta);
    if (!id) return;
    if (!seen.has(id)) seen.set(id, { count:0, worstSev:'m' });
    const entry = seen.get(id);
    entry.count++;
    if ((sevRank[f.sev]||0) > (sevRank[entry.worstSev]||0)) entry.worstSev = f.sev;
  });

  if (!seen.size) { card.style.display = 'none'; return; }
  card.style.display = '';

  // "All TTPs" pill
  let html = `<span class="tsp tsp-all ${activeKeepTTP==='all'?'tsp-on':''}" onclick="selectKeepTTP('all')">
    All TTPs
    <span class="tsp-badge">${d.findings.length}</span>
  </span>`;

  seen.forEach((entry, ttpId) => {
    const name = ttpShortName(ttpId);
    const isOn = activeKeepTTP === ttpId;
    html += `<span class="tsp ${isOn?'tsp-on':''}" onclick="selectKeepTTP('${ttpId}')">
      <span class="tsp-dot ${entry.worstSev}"></span>
      <span class="tsp-id">${ttpId}</span>
      ${name ? `<span class="tsp-name">${name}</span>` : ''}
      <span class="tsp-badge">${entry.count}</span>
    </span>`;
  });

  pillsEl.innerHTML = html;
}

function selectKeepTTP(ttpId) {
  activeKeepTTP = ttpId;
  const d = keepData[activeKeepHunt];
  if (!d) return;
  // Update pills active state
  document.querySelectorAll('.tsp').forEach(el => el.classList.remove('tsp-on'));
  const target = [...document.querySelectorAll('.tsp')].find(el =>
    el.onclick?.toString().includes(`'${ttpId}'`)
  );
  if (target) target.classList.add('tsp-on');
  // Update header label
  const lbl = document.getElementById('keep-ttp-scope-label');
  if (lbl) lbl.innerHTML = ttpId === 'all'
    ? '<b>All TTPs</b>'
    : `<b>${ttpId}</b>${ttpShortName(ttpId) ? ' — ' + ttpShortName(ttpId) : ''}`;
  renderKeepFindings(d);
  renderKeepTimeline(d);
  renderHuntReport(activeKeepHunt);
}

function renderKeepFindings(d) {
  const filtered = activeKeepTTP === 'all'
    ? d.findings
    : d.findings.filter(f => extractTTP(f.meta) === activeKeepTTP);

  const crits = filtered.filter(f => f.sev === 'c').length;
  const highs = filtered.filter(f => f.sev === 'h').length;

  // Title + chips
  const titleSuffix = activeKeepTTP === 'all' ? d.title : activeKeepTTP;
  document.getElementById('keep-findings-title').textContent = 'Findings — ' + titleSuffix;
  document.getElementById('keep-crit-chip').textContent = crits + ' Critical';
  document.getElementById('keep-high-chip').textContent = highs + ' High';

  // Scope counts chip in selector header
  const sc = document.getElementById('keep-ttp-scope-counts');
  if (sc) sc.innerHTML = crits
    ? `<span class="chip chip-red" style="font-size:9px;">${crits} Critical</span>`
    + (highs ? ` <span class="chip chip-yellow" style="font-size:9px;">${highs} High</span>` : '')
    : highs ? `<span class="chip chip-yellow" style="font-size:9px;">${highs} High</span>` : '';

  const fl = document.getElementById('keep-findings-list');
  const huntComments = findingComments[activeKeepHunt] || {};
  const usersObj = typeof users !== 'undefined' ? users : {};

  if (!filtered.length) {
    fl.innerHTML = `<div style="padding:20px;text-align:center;font-size:11px;color:var(--muted);">No findings for ${activeKeepTTP} in this hunt.</div>`;
  } else {
    const fullFindings = d.findings;
    fl.innerHTML = filtered.map(f => {
      const globalIdx = fullFindings.indexOf(f);
      const comments = huntComments[globalIdx] || [];
      const commentCount = comments.length;
      const tagMap = { conf:'conf', fp:'fp', inv:'inv' };
      const threadHTML = comments.map(c => {
        const u = usersObj[c.author] || { color:'#4e6180', initials: (c.author||'?')[0].toUpperCase() };
        const tagEl = c.tag === 'conf'
          ? `<span class="fc-tag-conf">✓ Confirmed</span>`
          : c.tag === 'fp'
          ? `<span class="fc-tag-fp">FP</span>` : '';
        return `<div style="display:flex;gap:7px;align-items:flex-start;">
          <div class="fc-av" style="background:${u.bg||u.color+'20'};color:${u.color};">${u.initials}</div>
          <div class="fc-bubble">
            <div style="display:flex;align-items:center;gap:6px;margin-bottom:3px;">
              <span style="font-size:11px;font-weight:600;color:var(--text);">${c.author}</span>
              <span style="font-size:10px;color:var(--muted);">${c.ts}</span>
              ${tagEl}
            </div>
            <div style="font-size:11px;color:var(--sub);line-height:1.5;">${c.text}</div>
          </div>
        </div>`;
      }).join('');
      const isOpen = openFindingComments[activeKeepHunt + '-' + globalIdx];
      return `<div style="padding:10px 14px;border-bottom:1px solid var(--border);">
        <div class="fr-inner" onclick="openAgentDrawer('${f.drawer}')" style="cursor:pointer;">
          <div class="sev-pip ${f.sev}"></div>
          <div class="fr-content">
            <div class="fr-title">${f.title}</div>
            <div class="fr-meta">${f.meta}</div>
          </div>
        </div>
        <div>
          <span class="fc-toggle" onclick="toggleFindingComments('${activeKeepHunt}',${globalIdx})">
            💬 ${commentCount ? commentCount + ' comment' + (commentCount > 1 ? 's' : '') : 'Add comment'}
            <span style="font-size:9px;">${isOpen ? '▲' : '▼'}</span>
          </span>
        </div>
        <div class="fc-thread${isOpen ? ' open' : ''}" id="fc-thread-${activeKeepHunt}-${globalIdx}">
          ${threadHTML}
          <div style="display:flex;gap:6px;align-items:center;margin-top:2px;">
            <input class="fc-input" id="fc-inp-${activeKeepHunt}-${globalIdx}" placeholder="Add a note… (Enter to save)" onkeydown="if(event.key==='Enter')addFindingComment('${activeKeepHunt}',${globalIdx})">
            <select id="fc-tag-${activeKeepHunt}-${globalIdx}" style="background:var(--s2);border:1px solid var(--border);border-radius:4px;padding:4px 6px;font-size:11px;color:var(--sub);outline:none;">
              <option value="">No tag</option>
              <option value="conf">✓ Confirmed</option>
              <option value="fp">FP</option>
              <option value="inv">Investigating</option>
            </select>
            <button class="btn btn-primary btn-sm" onclick="addFindingComment('${activeKeepHunt}',${globalIdx})">+</button>
          </div>
        </div>
      </div>`;
    }).join('');
  }

  // Collapsed summary
  const fs = document.getElementById('findings-summary');
  if (fs) fs.textContent = `${filtered.length} findings · ${crits} Critical · ${highs} High`;
}

function toggleFindingComments(huntId, idx) {
  const key = huntId + '-' + idx;
  openFindingComments[key] = !openFindingComments[key];
  const thread = document.getElementById('fc-thread-' + key);
  if (thread) thread.classList.toggle('open', !!openFindingComments[key]);
  // re-render to update toggle arrow text
  const d = keepData[huntId];
  if (d) renderKeepFindings(d);
}

function addFindingComment(huntId, idx) {
  const key = huntId + '-' + idx;
  const inp = document.getElementById('fc-inp-' + key);
  const tagSel = document.getElementById('fc-tag-' + key);
  if (!inp) return;
  const text = inp.value.trim();
  if (!text) return;
  if (!findingComments[huntId]) findingComments[huntId] = {};
  if (!findingComments[huntId][idx]) findingComments[huntId][idx] = [];
  const now = new Date();
  const ts = now.toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' });
  findingComments[huntId][idx].push({
    author: currentUser || 'analyst',
    ts,
    text,
    tag: tagSel ? tagSel.value || null : null,
  });
  openFindingComments[key] = true;
  inp.value = '';
  const d = keepData[huntId];
  if (d) renderKeepFindings(d);
}

function toggleTimelineView(v) {
  activeTimelineView = v;
  ['list','swim'].forEach(k => {
    const btn = document.getElementById('tlv-' + k);
    if (btn) btn.classList.toggle('on', k === v);
  });
  const d = keepData[activeKeepHunt];
  if (d) renderKeepTimeline(d);
}

function renderSwimlane(filtered) {
  if (!filtered.length) return '<div style="font-size:11px;color:var(--muted);padding:10px 0;">No timeline events.</div>';

  // Collect ordered unique hosts
  const hostOrder = [];
  filtered.forEach(t => { if (t.host && !hostOrder.includes(t.host)) hostOrder.push(t.host); });

  // Parse times to compute axis
  const toMin = ts => {
    const [h,m] = ts.split(':').map(Number);
    return h * 60 + m;
  };
  const times = filtered.map(t => toMin(t.time));
  const minT = Math.min(...times);
  const maxT = Math.max(...times);
  const span = Math.max(maxT - minT, 10); // avoid div/0

  // Build tick labels (up to 5 ticks)
  const tickCount = Math.min(5, filtered.length);
  const ticks = Array.from({length: tickCount}, (_, i) => {
    const pct = i / (tickCount - 1) * 100;
    const m = Math.round(minT + (i / (tickCount - 1)) * span);
    const h = Math.floor(m / 60).toString().padStart(2,'0');
    const mm = (m % 60).toString().padStart(2,'0');
    return `<div class="swimlane-tick" style="left:${pct}%">${h}:${mm}</div>`;
  });

  const colorMap = {
    red:'var(--red)', blue:'var(--blue)', orange:'var(--orange)',
    yellow:'var(--yellow)', indigo:'var(--indigo)', green:'var(--green)',
    teal:'var(--teal)'
  };

  const lanes = hostOrder.map(host => {
    const evts = filtered.filter(t => t.host === host);
    const evtsHTML = evts.map(t => {
      const pct = span > 0 ? ((toMin(t.time) - minT) / span) * 100 : 50;
      const bg = colorMap[t.color] || 'var(--sub)';
      const label = (t.tag || t.text.slice(0, 30)) + (t.text.length > 30 && !t.tag ? '…' : '');
      return `<div class="swimlane-evt" style="left:${pct}%;background:${bg};">
        <div class="swimlane-tooltip">${t.time}${t.tag ? ' · ' + t.tag : ''} — ${t.text.slice(0,45)}${t.text.length>45?'…':''}</div>
      </div>`;
    }).join('');
    return `<div class="swimlane-lane">
      <div class="swimlane-lane-lbl">${host}</div>
      <div class="swimlane-track">
        <div class="swimlane-baseline"></div>
        ${evtsHTML}
      </div>
    </div>`;
  }).join('');

  return `<div class="swimlane-wrap"><div class="swimlane">
    <div class="swimlane-axis">${ticks.join('')}</div>
    ${lanes}
  </div></div>`;
}

function renderKeepTimeline(d) {
  const filtered = activeKeepTTP === 'all'
    ? d.timeline
    : d.timeline.filter(t => !t.tag || t.tag === activeKeepTTP);

  const tl = document.getElementById('keep-timeline');
  if (!filtered.length) {
    tl.innerHTML = `<div style="font-size:11px;color:var(--muted);padding:10px 0;">No timeline events for ${activeKeepTTP}.</div>`;
  } else if (activeTimelineView === 'swim') {
    tl.innerHTML = renderSwimlane(filtered);
  } else {
    tl.innerHTML = filtered.map((t, i) =>
      `<div class="tl-row">
        <div class="tl-spine">
          <div class="tl-dot" style="background:var(--${t.color})"></div>
          ${i < filtered.length - 1 ? '<div class="tl-line"></div>' : ''}
        </div>
        <div class="tl-body">
          <div class="tl-text">${t.text}</div>
          <div class="tl-time">${t.time}${t.tag ? ` <span class="tl-tag">${t.tag}</span>` : ''}${t.host ? `<span style="font-size:9px;color:var(--muted);margin-left:4px;">${t.host}</span>` : ''}</div>
        </div>
      </div>`
    ).join('');
  }

  const ts = document.getElementById('timeline-summary');
  if (ts) ts.textContent = `${filtered.length} events · last ${filtered[0]?.time || ''}`;
}

function addNote() {
  const inp = document.getElementById('note-input');
  const text = inp.value.trim();
  if (!text) return;
  const now = new Date();
  const ts = now.toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' }) +
             ' · ' + now.toLocaleDateString([], { month:'short', day:'numeric' });
  huntNotes[activeKeepHunt].unshift({ text, ts, id: Date.now(), author: currentUser });
  inp.value = '';
  renderNotes();
}

function deleteNote(hunt, id) {
  huntNotes[hunt] = huntNotes[hunt].filter(n => n.id !== id);
  renderNotes();
}

function renderNotes() {
  const notes = huntNotes[activeKeepHunt];
  const list = document.getElementById('notes-list');
  const countEl = document.getElementById('keep-notes-count');
  const noteLabel = notes.length + (notes.length === 1 ? ' note' : ' notes');
  countEl.textContent = noteLabel;
  const ns = document.getElementById('notes-summary');
  if (ns) ns.textContent = noteLabel;
  if (!notes.length) {
    list.innerHTML = '<div style="font-size:11px;color:var(--muted);text-align:center;padding:10px 0;">No notes yet for this hunt.</div>';
    return;
  }
  list.innerHTML = notes.map(n => {
    const u = users[n.author] || users.alice;
    const isOwn = n.author === currentUser;
    return `<div class="note-item${isOwn ? ' own-note' : ''}">
      <div class="note-author-row">
        ${avatarHTML(n.author)}
        <div>
          <span class="note-author-name">${u.name}</span>
          <span class="note-author-role" style="margin-left:5px;">${u.role}</span>
        </div>
        ${isOwn ? `<button class="note-del" style="margin-left:auto;" onclick="deleteNote('${activeKeepHunt}',${n.id})" title="Delete note">✕</button>` : ''}
      </div>
      <div class="note-text">${n.text.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>
      <div class="note-meta"><span>${n.ts} · ${keepData[activeKeepHunt].title}</span></div>
    </div>`;
  }).join('');
  renderPostingAs();
}

// ── Init ──
renderKeepHunt('041');
