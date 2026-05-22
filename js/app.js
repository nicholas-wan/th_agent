/* ════════════════════════════════════════════════════════════════════════
   PrimeTH ATHF — Application Logic
   Edit this file to change behaviour. Loaded by index.html via <script src>.
   KB data (skills, runbooks, env, IOCs, gate decisions) live in kb/*.js
   ════════════════════════════════════════════════════════════════════════ */
// ── Tab switching ──
function goTab(name, el) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('on'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('on'));
  document.getElementById('pane-' + name).classList.add('on');
  if (el) el.classList.add('on');
  // update mobile toggle label
  if (el) {
    const txt = el.childNodes[0].textContent.trim();
    const parts = txt.match(/^(\S+)\s+(.+)$/);
    document.getElementById('nav-current-icon').textContent = parts ? parts[1] : '☰';
    document.getElementById('nav-current-label').textContent = parts ? parts[2] : txt;
  }
  closeMobileNav();
}

// ── Hunt switcher dropdown ──
function toggleHuntSwitcher() {
  const btn  = document.getElementById('hunt-switch-btn');
  const menu = document.getElementById('hunt-switch-menu');
  btn.classList.toggle('open');
  menu.classList.toggle('open');
}
function closeHuntSwitcher() {
  document.getElementById('hunt-switch-btn').classList.remove('open');
  document.getElementById('hunt-switch-menu').classList.remove('open');
}
document.addEventListener('click', function(e) {
  if (!e.target.closest('#hunt-switch-wrap')) closeHuntSwitcher();
});

// ── Sub-tab switching (inside hunt-detail) ──
function goSubTab(name, el) {
  document.querySelectorAll('.sub-pane').forEach(p => p.classList.remove('on'));
  document.querySelectorAll('.sub-tab').forEach(t => t.classList.remove('on'));
  document.getElementById('subpane-' + name).classList.add('on');
  if (el) el.classList.add('on');
}

// ── Per-hunt Check tab metadata ──
const checkHuntMeta = {
  '041': {
    cti: 'CISA AA24-038A — Volt Typhoon',
    ttpCount: '14 TTPs',
    hypCount: '3 hypotheses under test',
    statusClass: 'chip-red', statusText: 'Volt Typhoon · Active',
    active: true,
  },
  '040': {
    cti: 'FBI-IC3 Alert — FIN7 BEC',
    ttpCount: '9 TTPs', hypCount: 'Hunt closed — 2 hypotheses archived',
    statusClass: 'chip-green', statusText: 'FIN7 Ransomware · Closed',
    active: false,
    closedMsg: 'This hunt closed on 2026-03-14. Detection queries and final results are archived in the <b>Keep</b> tab.',
  },
  '039': {
    cti: 'CISA Supply Chain Advisory',
    ttpCount: '7 TTPs', hypCount: 'Hunt closed — 2 hypotheses archived',
    statusClass: 'chip-green', statusText: 'Supply Chain · Closed',
    active: false,
    closedMsg: 'This hunt closed on 2026-02-28. Detection queries and final results are archived in the <b>Keep</b> tab.',
  },
  '038': {
    cti: 'Internal Intel — DNS Tunneling',
    ttpCount: '5 TTPs', hypCount: 'No hypotheses yet',
    statusClass: 'chip-gray', statusText: 'Draft',
    active: false,
    closedMsg: 'This hunt is in <b>draft</b> stage. Complete the Learn stage and approve the agent gate to generate hypotheses before running detections.',
  },
};

function resetCheckForHunt(huntId) {
  const keepId = huntId.replace('TH-2026-', '');
  const cm = checkHuntMeta[keepId] || {};

  // Update context strip
  document.getElementById('check-hunt-id').textContent = huntId;
  const sc = document.getElementById('check-hunt-status');
  sc.textContent = cm.statusText || huntId;
  sc.className = 'chip ' + (cm.statusClass || 'chip-gray');
  sc.style.fontSize = '10px';
  document.getElementById('check-hunt-cti').textContent = cm.cti || '';
  document.getElementById('check-hunt-ttps').textContent = cm.ttpCount || '';
  document.getElementById('check-hunt-hyps').textContent = cm.hypCount || '';

  // Always clear results
  document.getElementById('results-card').style.display = 'none';

  if (!cm.active) {
    const archivedSum = closedCheckSummaries[keepId];
    const archivedRAA = closedRAAResults[keepId];

    if (archivedSum) {
      // Closed hunt with archived results — show summary + RAA, collapse query runner
      renderCheckSummary(null, false, archivedSum);
      renderRAAResults(null, archivedRAA || null);
      // Collapse Detection Logic card — no need to re-run for closed hunts
      const qr = document.getElementById('query-runner-card');
      if (qr) qr.classList.add('card-collapsed');
    } else {
      // Draft or no archived data — show placeholder only
      const sumCard = document.getElementById('check-summary-card');
      sumCard.innerHTML = `<div class="card-head">
        <span class="card-title">📊 Check Summary</span>
        <span class="chip ${cm.statusClass || 'chip-gray'}" style="font-size:10px;">${cm.statusText || 'Inactive'}</span>
      </div>
      <div class="card-body">
        <div class="info-bar" style="margin:0;">
          <span class="ib-icon">ℹ️</span>
          <span>${cm.closedMsg || 'No active check data for this hunt.'}</span>
        </div>
      </div>`;
      sumCard.style.display = '';
      document.getElementById('raa-card').style.display = 'none';
    }
    return;
  }

  // Active hunt — reset hypothesis state and re-render
  checkQueryRun = {};
  activeQuery = 'h01';
  document.querySelectorAll('.check-hyp-btn').forEach(b => b.classList.remove('active-hyp'));
  const btn = document.getElementById('qbtn-h01');
  if (btn) btn.classList.add('active-hyp');
  document.getElementById('qeditor').value = queries['h01'] || '';
  const ql = document.getElementById('check-hyp-label');
  if (ql) ql.textContent = hypLabels['h01'] || '';
  const descEl = document.getElementById('query-desc-text');
  if (descEl && queryMeta['h01']) descEl.textContent = queryMeta['h01'].desc;
  renderCheckSummary('h01', false);
  renderQueryIterations('h01');
  renderRAAResults('h01');
}

// ── Hunt meta for detail pane header ──
const huntMeta = {
  'TH-2026-041': { status:'Volt Typhoon · Active', statusClass:'chip-red', title:'APT29 Lateral Movement & Credential Harvesting — Corp Domain', defaultTab:'learn' },
  'TH-2026-040': { status:'FIN7 Ransomware · Closed', statusClass:'chip-green', title:'Ransomware Pre-cursor BEC Activity — Finance Segment', defaultTab:'keep' },
  'TH-2026-039': { status:'Supply Chain · Closed', statusClass:'chip-green', title:'Supply Chain Compromise Indicators — DevOps Pipeline', defaultTab:'keep' },
  'TH-2026-038': { status:'Draft', statusClass:'chip-gray', title:'DNS Tunneling & C2 Beacon Detection — All Segments', defaultTab:'learn' },
};

function openHunt(id) {
  const m = huntMeta[id] || {};
  // Capture current sub-tab BEFORE any navigation changes the pane state
  const alreadyInDetail = document.getElementById('pane-hunt-detail')?.classList.contains('on');
  const preservedTab = alreadyInDetail
    ? (document.querySelector('.sub-tab.on')?.id?.replace('subtab-', '') || null)
    : null;

  document.getElementById('hd-id').textContent = id;
  const statusEl = document.getElementById('hd-status');
  statusEl.textContent = m.status || id;
  statusEl.className = 'chip ' + (m.statusClass || 'chip-gray');
  statusEl.style.fontSize = '10px';
  document.getElementById('hd-title').textContent = m.title || '';
  // Sync dropdown active state
  document.querySelectorAll('.hunt-switch-item').forEach(el => el.classList.remove('hsw-active'));
  const activeItem = document.getElementById('hsw-' + id);
  if (activeItem) activeItem.classList.add('hsw-active');
  // Navigate to hunt-detail pane, highlight Hunts nav tab (hunt-detail is a sub-view of Hunts)
  goTab('hunt-detail', document.querySelector('.nav-tab'));
  // Render observe data for this hunt
  const keepId = id.replace('TH-2026-', '');
  renderHuntObserve(keepId);
  // Don't preserve 'keep' tab for hunts with no Keep data (e.g., drafts) — redirect to their defaultTab
  const hasKeepData = !!keepData[keepId];
  const safePreserved = (preservedTab === 'keep' && !hasKeepData) ? null : preservedTab;
  const targetTab = safePreserved || m.defaultTab || 'learn';
  goSubTab(targetTab, document.getElementById('subtab-' + targetTab));
  // Sync Keep sub-pane to the selected hunt
  switchKeepHunt(keepId);
  // Reset Check sub-pane for the new hunt
  resetCheckForHunt(id);
}

// ── Mobile nav ──
function toggleMobileNav() {
  const nav = document.getElementById('topbar-nav');
  const backdrop = document.getElementById('nav-backdrop');
  const chevron = document.getElementById('nav-toggle-chevron');
  const open = nav.classList.toggle('mob-open');
  backdrop.classList.toggle('mob-open', open);
  chevron.textContent = open ? '▴' : '▾';
}
function closeMobileNav() {
  document.getElementById('topbar-nav').classList.remove('mob-open');
  document.getElementById('nav-backdrop').classList.remove('mob-open');
  document.getElementById('nav-toggle-chevron').textContent = '▾';
}

// ── Pipeline steps ──
let maxStep = -1;

function updateAgentPills(i) {
  const pills = [
    // step 0: report selected, pipeline starting
    { hyp:['Running','chip-blue',30,'Analysing CTI · 14 TTPs queued'],               orch:['Running','chip-blue',50,'Routing tasks · pipeline initialised'],  data:['Running','chip-blue',50,'Connecting to Splunk ES…'],              ts:['Waiting','chip-gray',0,'Awaiting TTPs'],               dl:['Waiting','chip-gray',0,'Awaiting tradecraft notes'] },
    // step 1: TTPs loaded from upstream pipeline, hypothesis agent working
    { hyp:['Running','chip-blue',70,'Cross-referencing past hunts · 3 recalled'],     orch:['Running','chip-blue',70,'Routing tasks · 2 agents active'],        data:['Done','chip-green',100,'Splunk data ready · indices available'], ts:['Waiting','chip-gray',0,'Awaiting hypotheses'],          dl:['Waiting','chip-gray',0,'Awaiting tradecraft notes'] },
    // step 2: hypotheses generated by Hypothesis Agent
    { hyp:['Done','chip-green',100,'3 hypotheses generated · handed to Orchestrator'],orch:['Done','chip-green',100,'Hypotheses routed · pipeline continues'],   data:['Done','chip-green',100,'Splunk data available · CIM-normalised'], ts:['Review','chip-blue',80,'3 hypotheses ready for review'], dl:['Waiting','chip-gray',0,'Awaiting tradecraft notes'] },
    // step 3: tradecraft running
    { hyp:['Done','chip-green',100,'3 hypotheses generated · analyst notes applied'], orch:['Done','chip-green',100,'Hunt coordinated · all tasks routed'],     data:['Done','chip-green',100,'Splunk data available · CIM-normalised'], ts:['Active','chip-blue',100,'Querying Splunk ES · 59 hits'],  dl:['Running','chip-blue',40,'Awaiting tradecraft notes'] },
    // step 4: detection logic + rule validation (via tool)
    { hyp:['Done','chip-green',100,'3 hypotheses generated · analyst notes applied'], orch:['Done','chip-green',100,'Hunt coordinated · all tasks routed'],     data:['Done','chip-green',100,'Splunk data available · CIM-normalised'], ts:['Done','chip-green',100,'Tradecraft analysis complete'],  dl:['Active','chip-blue',90,'Generating rules · validating via RuleVal tool…'] },
  ];
  const s = pills[Math.min(i, pills.length - 1)];
  function set(id, [chip, cls, pct, status]) {
    const el = document.getElementById(id);
    if (!el) return;
    el.style.opacity = '1';
    document.getElementById(id + '-status').textContent = status;
    document.getElementById(id + '-fill').style.width = pct + '%';
    const c = document.getElementById(id + '-chip');
    c.textContent = chip; c.className = 'chip ' + cls; c.style.fontSize = '10px';
  }
  set('ap-orch', s.orch);
  set('ap-hyp',  s.hyp);  set('ap-data', s.data);
  set('ap-ts',   s.ts);   set('ap-dl',   s.dl);
}

// ── Live agent feed ──
const feedAgents = {
  hyp:  { icon:'💡', name:'Hypothesis' },
  orch: { icon:'🎛️', name:'Orchestrator' },
  data: { icon:'🗄️', name:'Data Eng' },
  ts:   { icon:'🧠', name:'Tradecraft' },
  dl:   { icon:'⚙️',  name:'Detection Logic' },
};
const feedPfx = { tool:'→', reason:'↳', done:'✓', warn:'⚠', runbook:'📖', env:'🏗️', rv:'✅' };

const feedSteps = {
  0: [
    { type:'tool',   agent:'orch', msg:'pipeline initialised · routing to Data Engineering Agent' },
    { type:'tool',   agent:'data', msg:'connecting to Splunk ES via MCP server v2.1…' },
    { type:'done',   agent:'data', msg:'Splunk ES connected · indices ready: sysmon, windows, network, security' },
    { type:'tool',   agent:'orch', msg:'loading pre-extracted TTPs from upstream CTI pipeline for CISA AA24-038A…' },
    { type:'done',   agent:'orch', msg:'14 TTPs loaded · confidence scores applied · awaiting analyst' },
  ],
  1: [
    { type:'tool',   agent:'hyp',  msg:'search_hunts("T1078.002") → 3 past hunts with overlapping TTPs retrieved' },
    { type:'tool',   agent:'hyp',  msg:'get_hunt("TH-2026-038") → lateral movement · jsmith pivot confirmed · analyst notes loaded' },
    { type:'tool',   agent:'hyp',  msg:'check_coverage("T1078.002") → 1 existing rule · last hit 4 days ago · high confidence' },
    { type:'env',    agent:'orch', msg:'get_asset("WIN-DC01") → Tier-0 DC · 10.0.1.10 · DC VLAN · CrowdStrike 7.1' },
    { type:'env',    agent:'orch', msg:'get_account("jsmith") → Corp Workstations · off-hours anomaly flagged · MFA enrolled' },
    { type:'reason', agent:'hyp',  msg:'confidence on T1078.002 raised to 95% — off-hours logon pattern confirmed in TH-2026-038' },
    { type:'tool',   agent:'data', msg:'querying Splunk · EventCode 4769 baseline · last 30 days…' },
    { type:'done',   agent:'data', msg:'baseline established · 2.4M events in scope · CIM-normalised' },
    { type:'env',    agent:'data', msg:'get_segment("10.0.1.0/24") → Domain Controllers VLAN · Tier-0 · ACL: deny workstations' },
    { type:'reason', agent:'orch', msg:'recommending scope: T1078.002, T1570, T1003.001 · awaiting analyst approval' },
  ],
  2: [
    { type:'env',    agent:'hyp',  msg:'get_topology() → 8 segments · 10.0.0.0/8 scope · 2,412 endpoints' },
    { type:'env',    agent:'hyp',  msg:'get_asset("WIN-DC01") → Tier-0 DC · 10.0.1.10 · high-value asset' },
    { type:'env',    agent:'hyp',  msg:'get_account("jsmith") → Corp Workstations · off-hours anomaly · MFA enrolled' },
    { type:'tool',   agent:'hyp',  msg:'search_hunts("T1570") → TH-2026-038 confirmed · 9 hosts · jsmith pivot' },
    { type:'reason', agent:'hyp',  msg:'🎯 H-01 branch: Confirmed — elevating confidence · single-hop threshold pre-applied' },
    { type:'tool',   agent:'hyp',  msg:'search_hunts("T1558.003") → TH-2026-035 · 22% FP rate · BackupExec/MSSQLSvc SPNs' },
    { type:'reason', agent:'hyp',  msg:'🔔 H-02 branch: FPs in prior run — CMDB SPN exclusion list pre-loaded' },
    { type:'tool',   agent:'hyp',  msg:'search_hunts("T1071.001") → TH-2025-091 · clean run · no JA3 match' },
    { type:'reason', agent:'hyp',  msg:'❄️ H-03 branch: Clean prior run — net-new hypothesis · cert chain validation added' },
    { type:'done',   agent:'hyp',  msg:'3 hypotheses generated · 3 branches resolved · handing package to Orchestrator' },
    { type:'tool',   agent:'orch', msg:'hypothesis package received · routing H-01 to Tradecraft · awaiting analyst approval' },
  ],
  3: [
    { type:'tool',   agent:'ts',   msg:'skills_repo.load_skills(["T1570","T1003.001","T1558.003"]) → SK-045, SK-029, SK-038 matched' },
    { type:'reason', agent:'ts',   msg:'SK-045 (VMware vCenter LM): port 902/903 host-jump pattern active · scoping to vCenter segment' },
    { type:'reason', agent:'ts',   msg:'SK-029 (LSASS EDR Evasion): handle 0x1fffff via NtDuplicateObject · CrowdStrike + Defender excluded' },
    { type:'reason', agent:'ts',   msg:'SK-038 (Kerberoasting FP filter): BackupExec + MSSQLSvc SPN exclusions loaded · RC4 threshold tuned' },
    { type:'tool',   agent:'ts',   msg:'querying Splunk ES · EventCode 4769 TGS-REQ · 5m bucket · last 7d…' },
    { type:'runbook',agent:'ts',   msg:'get_runbook("T1570") → lateral tool transfer · 3 evidence tips · SPL template loaded' },
    { type:'tool',   agent:'ts',   msg:'running process chain analytic · 47 chains scored against baseline…' },
    { type:'reason', agent:'ts',   msg:'59 hits on T1570 · T1078.002 — CORP\\jsmith touched 14 hosts across 2 sessions' },
    { type:'tool',   agent:'ts',   msg:'querying LSASS access events (EventCode 10) · non-AV source images…' },
    { type:'runbook',agent:'ts',   msg:'get_runbook("T1003.001") → LSASS memory · critical: handle 0x1fffff · FP: exclude AV processes' },
    { type:'warn',   agent:'ts',   msg:'rundll32.exe accessed LSASS with handle 0x1fffff on WIN-DC01 · score 94' },
    { type:'done',   agent:'ts',   msg:'tradecraft complete · gaps: T1053.005, T1547.001, T1558.003 (RAA 0 hits) · passing to Detection Logic' },
  ],
  4: [
    { type:'runbook',agent:'dl',   msg:'get_runbook("T1053.005") → 2 SPL templates loaded · SCCM exclusion pattern retrieved' },
    { type:'tool',   agent:'dl',   msg:'generating SPL rule for T1053.005 — schtasks.exe /create pattern…' },
    { type:'tool',   agent:'dl',   msg:'loading SCCM ConfigMgr_* exclusion from TH-2025-091 (Alice Chen)…' },
    { type:'done',   agent:'dl',   msg:'T1053.005 rule complete · SCCM exclusion applied · est. FP rate <2%' },
    { type:'tool',   agent:'dl',   msg:'generating SPL rule for T1547.001 — Registry Run Key persistence…' },
    { type:'tool',   agent:'dl',   msg:'tuning T1558.003 Kerberoasting rule · applying BackupExec SPN exclusion…' },
    { type:'rv',     agent:'dl',   msg:'validate_rule("T1053.005-schtasks-create") → schema OK · FP rate 1.8% · PASS' },
    { type:'rv',     agent:'dl',   msg:'validate_rule("T1547.001-run-key-persist") → 1 field warning: registry_value_data → WARN' },
    { type:'rv',     agent:'dl',   msg:'validate_rule("T1558.003-kerberoasting") → schema OK · FP rate 0.4% · PASS' },
    { type:'done',   agent:'dl',   msg:'3 rules validated · 2 PASS · 1 WARN · pushing to Splunk ES deployment queue' },
  ],
};

const feedStepLabels = ['Select Intel','TTP Extraction','Hypotheses','Tradecraft','Detection Logic'];
let feedTimers = [];

function feedAddSep(label) {
  const feed = document.getElementById('agent-feed');
  if (!feed) return;
  const el = document.createElement('div');
  el.className = 'feed-sep';
  el.innerHTML = `<span style="color:var(--blue);font-size:8px;">●</span>${label}`;
  feed.appendChild(el);
  feed.scrollTop = feed.scrollHeight;
}

function feedAddEntry(type, agent, msg) {
  const feed = document.getElementById('agent-feed');
  if (!feed) return;
  const ag = feedAgents[agent] || {};
  const el = document.createElement('div');
  el.className = `feed-entry fe-${type}`;
  el.innerHTML = `<span class="fe-prefix">${feedPfx[type] || '→'}</span><div class="fe-body"><span class="fe-agent">${ag.icon} ${ag.name} · </span>${msg}</div>`;
  feed.appendChild(el);
  feed.scrollTop = feed.scrollHeight;
}

function playFeedStep(step) {
  const card = document.getElementById('learn-feed-card');
  if (card) card.style.display = '';
  feedTimers.forEach(clearTimeout);
  feedTimers = [];
  const entries = feedSteps[step] || [];
  feedAddSep(feedStepLabels[step] || 'Step ' + step);
  let delay = 0;
  entries.forEach(e => {
    delay += 380 + Math.random() * 320;
    feedTimers.push(setTimeout(() => feedAddEntry(e.type, e.agent, e.msg), delay));
  });
  // mark idle after last entry
  feedTimers.push(setTimeout(() => {
    const s = document.getElementById('feed-status');
    if (s) s.textContent = 'idle';
  }, delay + 600));
}

function setStep(i) {
  const isForward = i > maxStep;
  maxStep = Math.max(maxStep, i);
  for (let j = 0; j < 5; j++) {
    const n = document.getElementById('ps' + j);
    if (n) n.className = 'ps-node ' + (j === i ? 'curr' : j < i || j < maxStep ? 'done' : 'wait');
    if (j < 4) {
      const l = document.getElementById('pl' + j);
      if (l) l.className = 'ps-line' + (j < i || j < maxStep ? ' done' : '');
    }
    const s = document.getElementById('stage-' + j);
    if (s) s.className = 'stage card' + (j <= i ? ' show' : '');
  }
  updateAgentPills(maxStep);
  const stageLabels = ['Learn · Select Intel', 'Learn · TTP Extraction', 'Learn · Hypotheses', 'Learn · Tradecraft', 'Learn · Detection'];
  const stageEl = document.getElementById('lhc-stage');
  if (stageEl) stageEl.textContent = stageLabels[i] || stageLabels[0];
  if (maxStep >= 2) {
    const hypEl = document.getElementById('lhc-hyp');
    if (hypEl) { hypEl.textContent = '3 generated'; hypEl.style.color = ''; }
    const pastCard = document.getElementById('learn-past-card');
    if (pastCard) pastCard.style.display = '';
  }
  if (isForward) playFeedStep(i);
  // Scroll to the target stage (auto-expand if collapsed)
  const stageTarget = document.getElementById('stage-' + i);
  if (stageTarget) {
    stageTarget.classList.remove('collapsed');
    setTimeout(() => stageTarget.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50);
  }
}

// ── Intelligence Repository ──
const repoData = [
  { id: 'r1', icon: '🇺🇸', title: 'CISA AA24-038A — Volt Typhoon', source: 'CISA', actor: 'Volt Typhoon', date: '2024-02-07', ttps: 14, tags: ['APT', 'ICS/OT', 'Living off the Land'], techniques: ['T1078.002','T1570','T1003.001','T1558.003','T1071.001','T1041'] },
  { id: 'r2', icon: '🔴', title: 'Mandiant APT41 — Dual Espionage & Crimeware', source: 'Mandiant', actor: 'APT41', date: '2023-11-14', ttps: 22, tags: ['APT', 'Ransomware', 'Supply Chain'], techniques: ['T1195.002','T1059.001','T1055','T1486','T1562.001'] },
  { id: 'r3', icon: '🇰🇵', title: 'Lazarus Group — 3CX Supply Chain Attack', source: 'CrowdStrike', actor: 'Lazarus Group', date: '2023-04-20', ttps: 18, tags: ['Supply Chain', 'macOS', 'Windows'], techniques: ['T1195.002','T1547.001','T1059.004','T1071.001','T1041'] },
  { id: 'r4', icon: '🐻', title: 'FANCY BEAR — Credential Harvest Campaign', source: 'Recorded Future', actor: 'FANCY BEAR', date: '2024-01-09', ttps: 11, tags: ['APT', 'Phishing', 'Credential Access'], techniques: ['T1566.001','T1078','T1003','T1558','T1071'] },
  { id: 'r5', icon: '🕷️', title: 'SCATTERED SPIDER — Social Engineering TTPs', source: 'CISA', actor: 'SCATTERED SPIDER', date: '2023-11-16', ttps: 16, tags: ['Social Engineering', 'MFA Bypass', 'Cloud'], techniques: ['T1566','T1621','T1078.004','T1530','T1657'] },
  { id: 'r6', icon: '🇷🇺', title: 'Sandworm — Ukraine Power Grid Intrusion', source: 'ESET', actor: 'Sandworm', date: '2023-12-21', ttps: 20, tags: ['ICS/OT', 'Destructive', 'Ukraine'], techniques: ['T1078','T1059','T1485','T1565.003','T1498'] },
  { id: 'r7', icon: '💎', title: 'BlackCat/ALPHV — Healthcare Sector Targeting', source: 'HHS HC3', actor: 'BlackCat/ALPHV', date: '2024-02-27', ttps: 13, tags: ['Ransomware', 'Healthcare', 'Double Extortion'], techniques: ['T1486','T1490','T1070','T1078','T1071.001'] },
];

let repoSelected = null;

function renderRepo(items) {
  const list = document.getElementById('repo-list');
  list.innerHTML = items.map(r => `
    <div class="repo-item${repoSelected === r.id ? ' sel' : ''}" onclick="selectReport('${r.id}')">
      <div class="repo-item-icon">${r.icon}</div>
      <div class="repo-item-body">
        <div class="repo-item-title">${r.title}</div>
        <div class="repo-item-meta">
          <span>${r.source}</span>
          <span>·</span>
          <span>${r.date}</span>
          <span>·</span>
          <span style="color:var(--indigo)">${r.ttps} techniques</span>
          ${r.tags.map(t => `<span class="chip chip-gray" style="font-size:9px;padding:0 5px;">${t}</span>`).join('')}
        </div>
      </div>
      <div class="repo-item-action">
        ${repoSelected === r.id
          ? '<span class="chip chip-green" style="font-size:10px;">✓ Loaded</span>'
          : '<button class="btn btn-outline btn-sm" onclick="selectReport(\'' + r.id + '\');event.stopPropagation()">Load →</button>'}
      </div>
    </div>`).join('');
}

function filterRepo(q) {
  const s = q.toLowerCase();
  renderRepo(s ? repoData.filter(r =>
    r.title.toLowerCase().includes(s) ||
    r.actor.toLowerCase().includes(s) ||
    r.source.toLowerCase().includes(s) ||
    r.techniques.some(t => t.toLowerCase().includes(s)) ||
    r.tags.some(t => t.toLowerCase().includes(s))
  ) : repoData);
}

function selectReport(id) {
  repoSelected = id;
  activeReportId = id;
  const badge = document.getElementById('repo-loaded-badge');
  if (badge) { badge.textContent = '✓ Report Selected'; badge.className = 'chip chip-green'; badge.style.display = ''; }
  const customBtn = document.getElementById('custom-only-btn');
  if (customBtn) { customBtn.style.background = 'rgba(99,102,241,.12)'; customBtn.style.borderColor = 'rgba(99,102,241,.3)'; }
  renderRepo(repoData);
  const r = repoData.find(x => x.id === id);
  if (r) {
    const s0sum = document.getElementById('stage-0-summary-text');
    if (s0sum) s0sum.innerHTML = `${r.icon} <b>${r.title}</b> · <span style="color:var(--green);font-weight:600;">${r.ttps} TTPs</span> · ${r.source}`;
    document.getElementById('lhc-hunt').textContent = 'TH-2026-041';
    document.getElementById('lhc-cti').textContent = r.title.replace(/^[^ ]+ /, '');
    document.getElementById('lhc-ttps').textContent = r.ttps + ' extracted';
    document.getElementById('lhc-hyp').textContent = '—';
    document.getElementById('lhc-hyp').style.color = 'var(--muted)';
    document.getElementById('lhc-stage').textContent = 'Learn · Select Intel';
    document.getElementById('learn-hunt-context').style.display = '';
    document.getElementById('learn-agents-card').style.display = '';
    updateAgentPills(0);
    const feedStatus = document.getElementById('feed-status');
    if (feedStatus) feedStatus.textContent = 'streaming';
    playFeedStep(0);
  }
  setTimeout(() => {
    setStep(1);
    // Restore report mode visuals in Stage 1
    applyStage1Mode(false);
    renderSentencePanel(id);
  }, 400);
}

function startCustomOnlyHunt() {
  repoSelected = 'custom';
  activeReportId = null;
  // Stage 0 badge
  const badge = document.getElementById('repo-loaded-badge');
  if (badge) { badge.textContent = '✏️ Custom TTPs'; badge.className = 'chip chip-indigo'; badge.style.display = ''; }
  // Highlight the custom-only button, restore on report select
  const customBtn = document.getElementById('custom-only-btn');
  if (customBtn) { customBtn.style.background = 'rgba(99,102,241,.25)'; customBtn.style.borderColor = 'var(--indigo)'; }
  // Stage 0 summary
  const s0sum = document.getElementById('stage-0-summary-text');
  if (s0sum) s0sum.innerHTML = '✏️ <b>Custom TTPs only</b> <span style="color:var(--muted);font-weight:400;">· no threat intel report</span>';
  // Re-render repo list (no item highlighted)
  renderRepo(repoData);
  // Hunt context panel
  document.getElementById('lhc-hunt').textContent = 'TH-2026-041';
  document.getElementById('lhc-cti').textContent = 'Custom TTPs';
  document.getElementById('lhc-ttps').textContent = '—';
  document.getElementById('lhc-hyp').textContent = '—';
  document.getElementById('lhc-hyp').style.color = 'var(--muted)';
  document.getElementById('lhc-stage').textContent = 'Learn · Select Intel';
  document.getElementById('learn-hunt-context').style.display = '';
  document.getElementById('learn-agents-card').style.display = '';
  updateAgentPills(0);
  const feedStatus = document.getElementById('feed-status');
  if (feedStatus) feedStatus.textContent = 'streaming';
  playFeedStep(0);

  setTimeout(() => {
    setStep(1);
    applyStage1Mode(true);  // custom-only mode
    // Auto-open the custom TTP form
    const form = document.getElementById('custom-ttp-form');
    const btn  = document.getElementById('custom-ttp-toggle-btn');
    if (form && form.style.display === 'none') { form.style.display = ''; if (btn) btn.textContent = '✕ Cancel'; }
  }, 400);
}

// Toggle Stage 1 between report mode and custom-only mode
function applyStage1Mode(isCustom) {
  const reportSection = document.getElementById('report-ttp-section');
  const customNotice  = document.getElementById('custom-only-notice');
  const sentWrap      = document.getElementById('sent-panel-wrap');
  const reportChips   = document.getElementById('stage1-report-chips');
  const customChip    = document.getElementById('stage1-custom-chip');
  if (reportSection) reportSection.style.display = isCustom ? 'none' : '';
  if (customNotice)  customNotice.style.display  = isCustom ? ''     : 'none';
  if (sentWrap && isCustom) sentWrap.style.display = 'none'; // report mode: renderSentencePanel() shows it
  if (reportChips)   reportChips.style.display    = isCustom ? 'none' : '';
  if (customChip)    customChip.style.display     = isCustom ? ''     : 'none';
}

// ── Stage collapse toggle ──
function toggleStage(id, event) {
  if (event && event.target.closest('.btn')) return; // don't collapse when clicking buttons
  document.getElementById(id).classList.toggle('collapsed');
}

// ── Agent gate controls ──
function agentApprove(nextStep) {
  setStep(nextStep);
}

function agentModify(gateId) {
  document.getElementById(gateId + '-modify').classList.toggle('open');
}

function agentApplyModify(nextStep, gateId) {
  document.getElementById(gateId + '-modify').classList.remove('open');
  setStep(nextStep);
}

function agentOverride(currentStage, nextStep) {
  const head = document.querySelector('#stage-' + currentStage + ' .card-head');
  if (head && !head.querySelector('.override-chip')) {
    const chip = document.createElement('span');
    chip.className = 'chip chip-yellow override-chip';
    chip.style.cssText = 'font-size:10px;margin-left:6px;';
    chip.textContent = '↗ Analyst override';
    head.appendChild(chip);
  }
  setStep(nextStep);
}

function selHyp(el) {
  document.querySelectorAll('.hyp-card').forEach(h => h.classList.remove('sel'));
  el.classList.add('sel');
}

// ── Run Pipeline simulation ──
function runPipeline() {
  const btn = document.getElementById('run-pipeline-btn');
  // Navigate to hunt-detail pane, Learn sub-tab
  openHunt('TH-2026-041');
  goSubTab('learn', document.getElementById('subtab-learn'));

  // Disable button during run
  btn.disabled = true;
  btn.textContent = '⏳ Running…';

  // Reset pipeline to step 0
  for (let j = 0; j < 5; j++) {
    const n = document.getElementById('ps' + j);
    if (n) n.className = 'ps-node ' + (j === 0 ? 'curr' : 'wait');
    if (j < 4) {
      const l = document.getElementById('pl' + j);
      if (l) l.className = 'ps-line';
    }
    const s = document.getElementById('stage-' + j);
    if (s) s.className = 'stage card' + (j === 0 ? ' show' : '');
  }
  const tsPill = document.getElementById('ts-pill');
  const dlPill = document.getElementById('dl-pill');
  if (tsPill) tsPill.style.opacity = '0.4';
  if (dlPill) dlPill.style.opacity = '0.4';

  const body = document.querySelector('.learn-body');
  const scrollToStage = (id) => {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  // Advance through each stage with delays
  const steps = [
    { delay: 1400, step: 1, stage: 'stage-1' },
    { delay: 3000, step: 2, stage: 'stage-2' },
    { delay: 4800, step: 3, stage: 'stage-3' },
    { delay: 6600, step: 4, stage: 'stage-4' },
  ];

  steps.forEach(({ delay, step, stage }) => {
    setTimeout(() => {
      setStep(step);
      scrollToStage(stage);
    }, delay);
  });

  // Re-enable button after full run
  setTimeout(() => {
    btn.disabled = false;
    btn.textContent = '▶ Run Pipeline';
  }, 7800);
}

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

// ── Query runner ──
const queries = {
  h01: `| H-01: PsExec Lateral Movement — Splunk ES (SPL)\nindex=windows (EventCode=7045 OR EventCode=4624 OR EventCode=4648)\n| eval hour=strftime(_time,"%H")\n| where hour>="22" OR hour<="06"\n| where NOT match(Account,"\\$$")\n| stats dc(host) as host_count, count as event_count by Account, EventCode, _time\n| where host_count > 3\n| eval risk_score=case(host_count>=10, 95, host_count>=5, 75, true(), 55)\n| sort - risk_score\n| table _time, Account, EventCode, host_count, event_count, risk_score`,
  h02: `| H-02: LSASS Memory Access — Splunk ES (SPL)\nindex=sysmon EventCode=10 TargetImage="*\\\\lsass.exe"\n| where match(GrantedAccess,"0x1010|0x1410|0x147a|0x1fffff")\n| stats count by _time, host, SourceImage, TargetImage, GrantedAccess, SourceProcessId\n| eval severity=if(count>5,"critical","high")\n| sort - count\n| table _time, host, SourceImage, GrantedAccess, SourceProcessId, severity`,
  h03: `| H-03: C2 Beacon JA3 Match — Splunk ES (SPL)\nindex=network dest_ip="185.220.101.47"\n| eval beacon_interval=_time-lag(_time,1,0) over (host)\n| stats avg(beacon_interval) as avg_interval, count, dc(src_ip) as src_count\n    by dest_ip, dest_port, ja3_hash\n| where avg_interval>55 AND avg_interval<65\n| eval confidence=round((1-(avg_interval-60)/60)*100,1)\n| sort - confidence\n| table dest_ip, dest_port, ja3_hash, avg_interval, count, confidence`
};
const queryMeta = {
  h01: {
    desc: 'Looks for off-hours authentication events (22:00–06:00 UTC) where a single account touches 3 or more distinct hosts. Characteristic of PsExec-style lateral movement — a compromised account reused to propagate across the network. Risk score scales with host count.',
    resultsMeta: '<span class="chip chip-red">14 hits</span><span class="chip chip-gray" style="font-size:10px;">0.43s</span>',
    resultsHead: '<tr><th>TimeGenerated</th><th>Account</th><th>Hosts</th><th>Events</th><th>Risk</th></tr>',
    resultsBody: `<tr><td>2026-04-27 09:38</td><td style="color:var(--red)">CORP\\jsmith</td><td>14</td><td>47</td><td><span class="chip chip-red" style="font-size:10px;">95</span></td></tr>
              <tr><td>2026-04-27 02:12</td><td>CORP\\svc-sql01</td><td>7</td><td>23</td><td><span class="chip chip-yellow" style="font-size:10px;">75</span></td></tr>
              <tr><td>2026-04-26 23:55</td><td>CORP\\admin-backup</td><td>5</td><td>18</td><td><span class="chip chip-yellow" style="font-size:10px;">75</span></td></tr>
              <tr><td>2026-04-26 01:34</td><td style="color:var(--red)">CORP\\jsmith</td><td>4</td><td>11</td><td><span class="chip chip-gray" style="font-size:10px;">55</span></td></tr>`,
    interp: '14 hits across 4 sessions. <b style="color:var(--red)">CORP\\jsmith</b> is the highest-risk account — 14 distinct hosts touched in one session, far exceeding the 3-host threshold; a second session the same day confirms persistent reuse. <b>svc-sql01</b> and <b>admin-backup</b> show similar patterns and should be reviewed for credential compromise. Recommend immediate isolation of jsmith and escalation to IR.',
  },
  h02: {
    desc: 'Detects processes accessing LSASS memory with handles commonly used by credential dumping tools. Filters on suspicious GrantedAccess masks (0x1010, 0x1410, 0x147a, 0x1fffff) indicating full or partial LSASS read rights. Any non-AV/EDR process touching LSASS this way is anomalous.',
    resultsMeta: '<span class="chip chip-red">3 hits</span><span class="chip chip-gray" style="font-size:10px;">0.61s</span>',
    resultsHead: '<tr><th>TimeGenerated</th><th>Host</th><th>Source Image</th><th>Access Mask</th><th>Severity</th></tr>',
    resultsBody: `<tr><td>2026-04-27 03:14</td><td>WIN-WS089</td><td style="color:var(--red);font-family:monospace;">rundll32.exe</td><td class="ttp-id">0x1fffff</td><td><span class="chip chip-red" style="font-size:10px;">critical</span></td></tr>
              <tr><td>2026-04-27 03:15</td><td>WIN-WS089</td><td style="font-family:monospace;">powershell.exe</td><td class="ttp-id">0x1010</td><td><span class="chip chip-yellow" style="font-size:10px;">high</span></td></tr>
              <tr><td>2026-04-26 22:48</td><td>WIN-DC01</td><td style="font-family:monospace;">msiexec.exe</td><td class="ttp-id">0x1410</td><td><span class="chip chip-yellow" style="font-size:10px;">high</span></td></tr>`,
    interp: '3 hits, all anomalous. <b style="color:var(--red)">rundll32.exe</b> on WIN-WS089 used a full-access handle (0x1fffff) — the broadest possible LSASS access, consistent with Mimikatz sekurlsa::logonpasswords. The subsequent powershell.exe hit on the same host 1 minute later suggests a staged dump-and-exfil sequence. The DC01 msiexec hit warrants investigation — msiexec has no business accessing LSASS on a domain controller.',
  },
  h03: {
    desc: 'Correlates outbound traffic to a known C2 IP (185.220.101.47) and measures inter-packet intervals. A beacon firing consistently near 60 seconds with a matching JA3 hash fingerprint is characteristic of a Cobalt Strike malleable profile. Low jitter indicates automated beaconing rather than human browsing.',
    resultsMeta: '<span class="chip chip-yellow">2 hits</span><span class="chip chip-gray" style="font-size:10px;">1.12s</span>',
    resultsHead: '<tr><th>Dest IP</th><th>Port</th><th>JA3 Hash</th><th>Avg Interval</th><th>Confidence</th></tr>',
    resultsBody: `<tr><td style="font-family:monospace;color:var(--red);">185.220.101.47</td><td>443</td><td class="ttp-id">769c10…</td><td>60.3s</td><td><span class="chip chip-yellow" style="font-size:10px;">94.2%</span></td></tr>
              <tr><td style="font-family:monospace;">185.220.101.47</td><td>8443</td><td class="ttp-id">769c10…</td><td>59.8s</td><td><span class="chip chip-yellow" style="font-size:10px;">96.7%</span></td></tr>`,
    interp: '2 beacon sessions confirmed to the same C2 IP across ports 443 and 8443. Both share JA3 hash <b>769c10…</b> — a known Cobalt Strike malleable profile fingerprint. Average intervals of 60.3s and 59.8s are well within CS default jitter range. The dual-port pattern suggests a primary + fallback channel. Recommend immediate network block of 185.220.101.47 and host isolation for the beaconing endpoints.',
  },
};
let activeQuery = 'h01';

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

// ── Check Summary — combined RAA + query assessment per hypothesis ──
const checkSummaryData = {
  h01: {
    pre: {
      status: 'chip-yellow', statusLabel: 'Query not run',
      tags: [
        { label: 'RAA', val: 'Triggered', cls: 'chip-red' },
        { label: 'Query', val: 'Not run', cls: 'chip-gray' },
        { label: 'Gaps', val: 'None identified', cls: 'chip-green' },
      ],
      assessment: 'RAA has already triggered on both analytics — <b>high-confidence T1570/T1078.002 indicators</b> are established from continuous monitoring. Run the H-01 SPL query to confirm with raw log evidence and quantify affected accounts. RAA and query are expected to be mutually reinforcing for this hypothesis.',
    },
    post: {
      status: 'chip-green', statusLabel: '✓ Assessment complete',
      tags: [
        { label: 'RAA', val: 'Triggered · 62 hits', cls: 'chip-red' },
        { label: 'Query', val: '14 hits', cls: 'chip-red' },
        { label: 'Gaps', val: 'None', cls: 'chip-green' },
      ],
      assessment: '<b>High-confidence lateral movement confirmed across all detection layers.</b> Command Line Anomaly (59 hits), Process Chain Anomaly (3 hits), and the H-01 SPL query (14 hits) independently surface the same T1570/T1078.002 activity — the convergence eliminates false-positive risk. No coverage gaps remain. Recommend immediate escalation to IR and isolation of <b style="color:var(--red)">CORP\\jsmith</b>.',
    },
  },
  h02: {
    pre: {
      status: 'chip-yellow', statusLabel: 'Query not run',
      tags: [
        { label: 'RAA', val: 'Partial', cls: 'chip-yellow' },
        { label: 'Query', val: 'Not run', cls: 'chip-gray' },
        { label: 'Gaps', val: 'T1558.003', cls: 'chip-yellow' },
      ],
      assessment: 'Process Chain Anomaly triggered on <b>T1003.001</b> (LSASS credential dump — WIN-WS089). However, <b>T1558.003 (Kerberoasting)</b> is outside RAA scope — TGS-REQ patterns live in authentication logs, not process chains. <b>This is a coverage gap.</b> Run the H-02 query to fill it with direct Kerberos ticket-request evidence from EventCode 4769.',
    },
    post: {
      status: 'chip-green', statusLabel: '✓ Assessment complete',
      tags: [
        { label: 'RAA', val: 'Partial', cls: 'chip-yellow' },
        { label: 'Query', val: '3 hits', cls: 'chip-red' },
        { label: 'Gaps', val: 'Closed by query', cls: 'chip-green' },
      ],
      assessment: '<b>Combined assessment complete — RAA gap closed by detection query.</b> T1003.001 confirmed by Process Chain Anomaly (rundll32.exe / 0x1fffff LSASS handle). The H-02 query filled the T1558.003 gap via Kerberos access log analysis. Both credential-theft TTPs are now evidenced. Recommend credential rotation across CORP domain and full forensics on WIN-WS089 and WIN-DC01.',
    },
  },
  h03: {
    pre: {
      status: 'chip-gray', statusLabel: 'Query not run',
      tags: [
        { label: 'RAA', val: 'Not applicable', cls: 'chip-gray' },
        { label: 'Query', val: 'Not run', cls: 'chip-gray' },
        { label: 'Gaps', val: 'RAA N/A', cls: 'chip-gray' },
      ],
      assessment: 'RAA is <b>not applicable</b> for T1071.001 — C2 beacon detection requires network-layer telemetry (JA3/JA3S fingerprints, inter-packet intervals) that is outside process and command-line analytic scope. <b>The H-03 SPL query is the sole detection path</b> for this hypothesis. This is expected — not all techniques are addressable by host-based analytics.',
    },
    post: {
      status: 'chip-green', statusLabel: '✓ Assessment complete',
      tags: [
        { label: 'RAA', val: 'Not applicable', cls: 'chip-gray' },
        { label: 'Query', val: '2 sessions confirmed', cls: 'chip-yellow' },
        { label: 'Gaps', val: 'RAA N/A — by design', cls: 'chip-gray' },
      ],
      assessment: '<b>Query-only assessment — RAA not applicable for network-layer technique.</b> H-03 SPL confirmed 2 active beacon sessions to 185.220.101.47 with JA3 hash matching a known Cobalt Strike malleable profile. The absence of RAA results is expected for T1071.001 — this is full detection coverage given available telemetry. Recommend immediate network block and endpoint isolation for beaconing hosts.',
    },
  },
};
let checkQueryRun = {};   // tracks per-hypothesis post-run state

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

function renderCheckSummary(hypId, postRun, dataOverride) {
  const card = document.getElementById('check-summary-card');
  if (!card) return;
  let s, subtitle;
  if (dataOverride) {
    s = dataOverride;
    subtitle = 'Archived results — hunt closed';
  } else {
    const d = checkSummaryData[hypId];
    if (!d) { card.style.display = 'none'; return; }
    s = postRun ? d.post : d.pre;
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

// ── RAA (Reasoning Augmented Analytics) results per hypothesis ──
const raaResults = {
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

function renderRAAResults(hypId, dataOverride) {
  const card = document.getElementById('raa-card');
  if (!card) return;
  const d = dataOverride !== undefined ? dataOverride : raaResults[hypId];
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

const hypLabels = {
  h01: 'H-01 · PsExec Lateral Movement — TH-2026-041',
  h02: 'H-02 · LSASS + Kerberoasting — TH-2026-041',
  h03: 'H-03 · C2 Beacon JA3 Match — TH-2026-041',
};
function renderQueryIterations(id) {
  const card = document.getElementById('agent-reasoning-card');
  if (!card) return;
  const chains = queryIterations[id];
  if (!chains || chains.length === 0) { card.style.display = 'none'; return; }
  card.style.display = '';
  const chipCls  = { PASS:'chip-green', WARN:'chip-yellow', FAIL:'chip-red' };
  const badgeCls = { PASS:'pass', WARN:'warn', FAIL:'fail' };
  // Metric label colour: too-many=orange, no-results=indigo, warn=yellow, pass=green
  function metricStyle(iter) {
    if (iter.badge === 'PASS') return 'color:var(--green)';
    if (iter.badge === 'WARN') return 'color:var(--yellow)';
    if (iter.failMode === 'no-results') return 'color:var(--indigo)';
    return 'color:var(--orange)'; // too-many (default FAIL)
  }
  // Icon prefix for the metric label
  function metricIcon(iter) {
    if (iter.badge === 'PASS') return '✓ ';
    if (iter.failMode === 'no-results') return '∅ ';
    if (iter.failMode === 'too-many') return '⚡ ';
    return '';
  }
  const totalIters = chains.reduce((a,c) => a + c.iters.length, 0);
  card.innerHTML = `
    <div class="card-head" style="cursor:default;">
      <div style="display:flex;flex-direction:column;gap:2px;">
        <span class="card-title">🔍 Agent Reasoning — Query Iterations</span>
        <span style="font-size:10px;color:var(--muted);">${totalIters} iteration${totalIters!==1?'s':''} across ${chains.length} rule chain${chains.length!==1?'s':''} · Detection Logic Agent</span>
      </div>
    </div>
    <div class="card-body" style="display:flex;flex-direction:column;gap:8px;">
      <div style="font-size:11px;color:var(--muted);line-height:1.5;">The Detection Logic Agent iterated on each rule until the alert volume was usable — collapsing from noise to signal. Expand a chain to see each attempt, whether it returned too many alerts or none, and what was adjusted.</div>
      ${chains.map(chain => `
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
            <pre class="det-iter-spl">${iter.spl}</pre>
            ${iter.reason ? `<div class="det-iter-reason">${iter.reason}</div>` : ''}
            ${iter.action ? `<div class="det-iter-action">${iter.action}</div>` : ''}
          </div>`).join('')}
        </div>
      </div>`).join('')}
    </div>`;
}

function setQ(id) {
  activeQuery = id;
  document.getElementById('qeditor').value = queries[id] || '';
  const m = queryMeta[id];
  if (m) document.getElementById('query-desc-text').textContent = m.desc;
  document.getElementById('results-card').style.display = 'none';
  // Update active button highlight
  document.querySelectorAll('.check-hyp-btn').forEach(b => b.classList.remove('active-hyp'));
  const activeBtn = document.getElementById('qbtn-' + id);
  if (activeBtn) activeBtn.classList.add('active-hyp');
  // Update subtitle label
  const lbl = document.getElementById('check-hyp-label');
  if (lbl) lbl.textContent = hypLabels[id] || id;
  // Update Detection Logic card summary
  const qrs = document.getElementById('qrunner-summary');
  const shortLabel = { h01:'H-01', h02:'H-02', h03:'H-03' }[id] || id;
  if (qrs) qrs.textContent = checkQueryRun[id]
    ? `${shortLabel} · ran · ${(queryMeta[id]?.resultsMeta || '').replace(/<[^>]+>/g,'').trim()}`
    : `${shortLabel} · not run yet`;
  // Render summary (restore post-run state if this hyp was already run)
  renderCheckSummary(id, !!checkQueryRun[id]);
  // Render agent reasoning chains for this hypothesis
  renderQueryIterations(id);
  // Render RAA results for this hypothesis
  renderRAAResults(id);
}
function runQuery() {
  const c = document.getElementById('results-card');
  c.style.display = 'none';
  const m = queryMeta[activeQuery];
  setTimeout(() => {
    c.style.display = '';
    if (m) {
      document.getElementById('results-meta').innerHTML = m.resultsMeta;
      document.getElementById('results-table').querySelector('thead tr').innerHTML = m.resultsHead.replace(/<tr>|<\/tr>/g,'');
      document.getElementById('results-table').querySelector('tbody').innerHTML = m.resultsBody;
      document.getElementById('result-interp-text').innerHTML = m.interp;
    }
    // Update summary to post-run state
    checkQueryRun[activeQuery] = true;
    renderCheckSummary(activeQuery, true);
    // Update Detection Logic card summary with hit count
    const qrs2 = document.getElementById('qrunner-summary');
    const sl2 = { h01:'H-01', h02:'H-02', h03:'H-03' }[activeQuery] || activeQuery;
    if (qrs2) qrs2.textContent = `${sl2} · ran · ${(m?.resultsMeta || '').replace(/<[^>]+>/g,'').trim()}`;
  }, 500);
}

// ── User accounts ──
const users = {
  alice:  { name:'Alice Chen',    initials:'AC', role:'Lead Threat Hunter', bg:'rgba(59,130,246,.22)',  color:'#3b82f6' },
  marcus: { name:'Marcus Webb',   initials:'MW', role:'Senior Analyst',      bg:'rgba(16,185,129,.22)', color:'#10b981' },
  priya:  { name:'Priya Sharma',  initials:'PS', role:'Threat Hunter',        bg:'rgba(245,158,11,.22)', color:'#f59e0b' },
  ryan:   { name:'Ryan Kowalski', initials:'RK', role:'SOC Analyst',          bg:'rgba(249,115,22,.22)', color:'#f97316' },
};
let currentUser = 'alice';

function avatarHTML(uid, size) {
  const u = users[uid]; if (!u) return '';
  const sz = size === 'lg' ? 'width:30px;height:30px;font-size:11px;' : 'width:24px;height:24px;font-size:9px;';
  return `<div class="user-av" style="${sz}background:${u.bg};color:${u.color};">${u.initials}</div>`;
}

function toggleModelMenu() {
  const menu = document.getElementById('model-menu');
  const isOpen = menu.classList.toggle('open');
  if (isOpen) document.getElementById('user-menu').classList.remove('open');
}

function selectModel(el, name, meta) {
  document.querySelectorAll('.model-menu-item').forEach(i => i.classList.remove('active-model'));
  el.classList.add('active-model');
  document.getElementById('model-badge-label').textContent = name;
  document.getElementById('model-menu').classList.remove('open');
}

function toggleUserMenu() {
  const menu = document.getElementById('user-menu');
  const isOpen = menu.classList.toggle('open');
  if (isOpen) document.getElementById('model-menu').classList.remove('open');
}

function switchUser(uid, e) {
  if (e) e.stopPropagation();
  currentUser = uid;
  const u = users[uid];
  // Update topbar
  document.getElementById('topbar-av').style.background = u.bg;
  document.getElementById('topbar-av').style.color = u.color;
  document.getElementById('topbar-av').textContent = u.initials;
  document.getElementById('topbar-name').textContent = u.name;
  // Update menu active state
  Object.keys(users).forEach(k => {
    const el = document.getElementById('um-' + k);
    if (el) el.classList.toggle('active-user', k === uid);
  });
  document.getElementById('user-menu').classList.remove('open');
  // Refresh "posting as" row
  renderPostingAs();
  renderNotes(); // re-render to update own-note highlights
}

function renderPostingAs() {
  const el = document.getElementById('posting-as-row');
  if (!el) return;
  const u = users[currentUser];
  el.innerHTML = `${avatarHTML(currentUser)}<span>Posting as <b style="color:var(--text);">${u.name}</b></span>`;
}

// Close menu when clicking outside
document.addEventListener('click', e => {
  const wrap = document.getElementById('user-menu-wrap');
  if (wrap && !wrap.contains(e.target)) {
    document.getElementById('user-menu').classList.remove('open');
  }
  const modelWrap = document.getElementById('model-menu-wrap');
  if (modelWrap && !modelWrap.contains(e.target)) {
    document.getElementById('model-menu').classList.remove('open');
  }
});

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
      l: 'Ingested CISA AA24-038A (Volt Typhoon). Extracted 14 ATT&amp;CK techniques. Generated 3 hypotheses focused on lateral movement, credential harvesting, and C2 beaconing.',
      o: 'H-01 confirmed (PsExec lateral movement — 14 hosts). H-02 likely (LSASS + Kerberoasting). H-03 under investigation (Cobalt Strike C2 profile match).',
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
      { color:'teal',   text:'<b>Hypothesis Agent</b> — 3 hypotheses generated from 14 TTPs · 3 past hunts recalled · coverage gaps flagged', time:'09:14', tag:'', host:'SYSTEM' },
    ],
    report: {
      status: 'Active', statusClass: 'chip-red',
      summary: 'This hunt targeted active APT29/Volt Typhoon intrusion activity across the corporate Windows domain. Over a 26-minute window, agents analysed authentication logs, Sysmon process telemetry, and network flow data against three hypotheses derived from the CISA AA24-038A advisory. All three hypotheses returned positive results, confirming a live, multi-stage intrusion involving lateral movement, credential harvesting, and an active C2 channel.',
      approach: 'H-01 (PsExec lateral movement) was confirmed first via off-hours authentication analysis — 14 distinct hosts were touched by a single compromised account (CORP\\jsmith) in two sessions, far exceeding the 3-host detection threshold. H-02 (credential harvesting) was confirmed via process chain anomaly: <span class="report-ioc">rundll32.exe</span> accessed LSASS with handle <span class="report-ioc">0x1fffff</span> from an <span class="report-ioc">explorer.exe</span> parent on WIN-DC01, consistent with Mimikatz sekurlsa::logonpasswords. H-03 (C2 beacon) was confirmed by JA3 fingerprint match — beacon interval 60.1s, watermark <span class="report-ioc">0x4e4b5547</span>, destination <span class="report-ioc">185.220.101.47:443</span>.',
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
  renderVelocityCard(id);
  renderGateDecisionLog(id);

  // Similar hunts summary
  const ss = document.getElementById('simhunts-summary');
  if (ss) ss.textContent = document.getElementById('sim-hunt-count')?.textContent || '';

  // Refresh notes
  renderNotes();
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

function renderVelocityCard(huntId) {
  const el = document.getElementById('velocity-body');
  if (!el) return;
  const shortId = huntId.replace('TH-2026-', '');
  const v = velocityData[shortId];
  if (!v) { el.innerHTML = '<div style="font-size:11px;color:var(--muted);">No velocity data for this hunt.</div>'; return; }

  const trendIcon = v.fpTrend === 'down' ? '↓' : v.fpTrend === 'up' ? '↑' : '→';
  const trendColor = v.fpTrend === 'down' ? 'var(--green)' : v.fpTrend === 'up' ? 'var(--red)' : 'var(--muted)';

  const mttdMax = Math.max(...v.mttdBars);
  const fpMax   = Math.max(...v.fpBars);

  function sparkline(bars, max, color) {
    return bars.map(b => {
      const h = Math.max(3, Math.round((b / max) * 20));
      return `<div class="vel-bar" style="height:${h}px;background:${color};"></div>`;
    }).join('');
  }

  el.innerHTML = `
    <div class="vel-grid">
      <div class="vel-item">
        <div class="vel-val">${v.mttd}</div>
        <div class="vel-lbl">Mean Time to Detect</div>
        <div class="vel-sparkline">${sparkline(v.mttdBars, mttdMax, 'var(--blue)')}</div>
      </div>
      <div class="vel-item">
        <div class="vel-val">${v.h2rule}</div>
        <div class="vel-lbl">Hyp → Rule Time</div>
        <div class="vel-sparkline">${sparkline([...v.mttdBars].map(b=>b*.45), mttdMax*.45, 'var(--indigo)')}</div>
      </div>
      <div class="vel-item" style="grid-column:1/-1;">
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <div>
            <div class="vel-val">${v.fpRate} <span style="font-size:12px;color:${trendColor};">${trendIcon}</span></div>
            <div class="vel-lbl">False Positive Rate</div>
          </div>
          <div class="vel-sparkline" style="width:70px;">${sparkline(v.fpBars, fpMax, 'var(--yellow)')}</div>
        </div>
      </div>
    </div>
    <div style="margin-top:8px;font-size:10px;color:var(--muted);text-align:center;">Last 3 hunts · same TTP cluster</div>`;
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

// ── Drawer data ──
const agentData = {
  hypothesis: { title:'Hypothesis Agent', sub:'Threat Hypothesis Generation · Completed · spawned by Orchestrator', body:`
    <div class="ds"><div class="ds-head">Role</div><div class="reasoning">The Hypothesis Agent is the first agent in the hunt pipeline. It reads incoming CTI reports, maps extracted TTPs to the MITRE ATT&CK framework, cross-references past hunt findings via the Past Hunts MCP tool, and generates structured, evidence-backed hunt hypotheses. Each hypothesis includes a confidence score, linked TTPs, supporting CTI sentences, and pre-applied analyst notes from prior runs. Output is handed off to the Orchestrator for scoping and routing.</div></div>
    <div class="ds"><div class="ds-head">🔌 Tools Used</div>
      <div class="ioc-row"><span class="ioc-t">📖</span>Technique Runbook — <code style="font-size:10px;color:var(--green);">get_runbook(ttp_id)</code> × 14 calls</div>
      <div class="ioc-row"><span class="ioc-t">🗂️</span>Past Hunts — <code style="font-size:10px;color:var(--blue);">search_hunts(ttp)</code> × 3 calls · <code style="font-size:10px;color:var(--blue);">get_hunt(id)</code> × 2 calls</div>
      <div class="ioc-row"><span class="ioc-t">🛡️</span>Coverage Checker — <code style="font-size:10px;color:#f59e0b;">check_coverage(ttp)</code> × 14 calls</div>
      <div class="ioc-row"><span class="ioc-t">🏗️</span>Environment Context — <code style="font-size:10px;color:var(--indigo);">get_topology()</code> · <code style="font-size:10px;color:var(--indigo);">get_asset(host)</code> × 2 · <code style="font-size:10px;color:var(--indigo);">get_account(user)</code> × 1</div>
    </div>
    <div class="ds"><div class="ds-head">Environment Loaded</div>
      <div class="ioc-row"><span class="ioc-t">🌐</span>10.0.0.0/8 scope · 8 segments · 2,412 endpoints · 34 servers</div>
      <div class="ioc-row"><span class="ioc-t">🖥</span>WIN-DC01 — Tier-0 DC · 10.0.1.10 · high-value asset · CrowdStrike 7.1</div>
      <div class="ioc-row"><span class="ioc-t">👤</span>jsmith — Corp Workstations · <span style="color:var(--yellow);">off-hours anomaly</span> · MFA enrolled</div>
    </div>
    <div class="ds"><div class="ds-head">Past Hunt Branch Decisions</div>
      <div class="ioc-row" style="flex-direction:column;align-items:flex-start;gap:3px;">
        <div style="display:flex;align-items:center;gap:6px;">
          <span style="font-size:10px;font-weight:700;color:var(--sub);min-width:28px;">H-01</span>
          <span style="font-size:12px;">🎯</span>
          <span class="hyp-branch-label hbl-confirmed">Confirmed</span>
          <code style="font-size:10px;color:var(--muted);">TH-2026-038 · TH-2026-035</code>
        </div>
        <div style="font-size:10px;color:var(--sub);padding-left:35px;line-height:1.5;">PsExec confirmed across 9 hosts · jsmith pivot validated</div>
        <div style="font-size:10px;color:#a78bfa;padding-left:35px;">↳ Confidence elevated · single-hop threshold + batch exclusion pre-applied</div>
      </div>
      <div class="ioc-row" style="flex-direction:column;align-items:flex-start;gap:3px;margin-top:6px;">
        <div style="display:flex;align-items:center;gap:6px;">
          <span style="font-size:10px;font-weight:700;color:var(--sub);min-width:28px;">H-02</span>
          <span style="font-size:12px;">🔔</span>
          <span class="hyp-branch-label hbl-fp">FPs in prior run</span>
          <code style="font-size:10px;color:var(--muted);">TH-2026-035</code>
        </div>
        <div style="font-size:10px;color:var(--sub);padding-left:35px;line-height:1.5;">Kerberoasting returned 22% FP rate — BackupExec/MSSQLSvc SPNs</div>
        <div style="font-size:10px;color:#a78bfa;padding-left:35px;">↳ CMDB SPN exclusion list pre-loaded · FP threshold tuned</div>
      </div>
      <div class="ioc-row" style="flex-direction:column;align-items:flex-start;gap:3px;margin-top:6px;">
        <div style="display:flex;align-items:center;gap:6px;">
          <span style="font-size:10px;font-weight:700;color:var(--sub);min-width:28px;">H-03</span>
          <span style="font-size:12px;">❄️</span>
          <span class="hyp-branch-label hbl-clean">Clean prior run</span>
          <code style="font-size:10px;color:var(--muted);">TH-2025-091</code>
        </div>
        <div style="font-size:10px;color:var(--sub);padding-left:35px;line-height:1.5;">No JA3 match in prior run · technique variant possible · Alice flagged cert chain gap</div>
        <div style="font-size:10px;color:#a78bfa;padding-left:35px;">↳ Net-new · cert chain validation added · confidence Medium</div>
      </div>
    </div>
    <div class="ds"><div class="ds-head">Coverage Gaps Flagged</div>
      <div style="font-size:11px;color:var(--sub);line-height:1.7;">
        <span style="color:var(--yellow);">T1547.001</span> Registry Run Key — no existing rule · flagged to Detection Logic Agent<br>
        <span style="color:var(--yellow);">T1053.005</span> Scheduled Task — RAA partial · 0 hits · new rule queued<br>
        <span style="color:var(--red);">T1021.006</span> WMI Lateral Movement — no telemetry · logging gap raised
      </div>
    </div>
    <div class="ds"><div class="ds-head">Run Stats</div>
      <div class="kv-grid">
        <span class="kv-k">TTPs analysed</span><span class="kv-v">14</span>
        <span class="kv-k">Past hunts recalled</span><span class="kv-v">3</span>
        <span class="kv-k">Runbook lookups</span><span class="kv-v">14</span>
        <span class="kv-k">Coverage checks</span><span class="kv-v">14</span>
        <span class="kv-k">Env context calls</span><span class="kv-v">4</span>
        <span class="kv-k">Branch: 🎯 Confirmed</span><span class="kv-v" style="color:var(--red);">1</span>
        <span class="kv-k">Branch: 🔔 FPs</span><span class="kv-v" style="color:var(--yellow);">1</span>
        <span class="kv-k">Branch: ❄️ Clean</span><span class="kv-v" style="color:var(--blue);">1</span>
        <span class="kv-k">Hypotheses output</span><span class="kv-v">3</span>
        <span class="kv-k">Completed</span><span class="kv-v">09:14</span>
      </div>
    </div>` },

  orchestrator: { title:'Orchestrator Agent', sub:'Hunt Coordination & Synthesis · Active', body:`
    <div class="ds"><div class="ds-head">Role</div><div class="reasoning">The Orchestrator is the central controller of the agentic pipeline. It receives the parsed CTI from the Data Engineering Agent, assigns analytical tasks to the RAA Supervisor Agent and Detection Logic Agent, collects their outputs, and synthesises a unified hunt picture for the analyst. It also manages escalation routing — currently flagging 3 critical signals to the IR queue.</div></div>
    <div class="ds"><div class="ds-head">Agent Topology</div>
      <div style="font-size:11px;color:var(--sub);line-height:2;">
        🎛️ Orchestrator<br>
        &nbsp;&nbsp;├─ 💡 Hypothesis Agent <span style="color:var(--muted);font-size:10px;">(spawned first · generates hypotheses)</span><br>
        &nbsp;&nbsp;├─ 🗄️ Data Engineering Agent<br>
        &nbsp;&nbsp;├─ 🧠 RAA Supervisor Agent<br>
        &nbsp;&nbsp;├─ ⚙️ Detection Logic Agent<br>
        &nbsp;&nbsp;└─ ✅ Rule Validation Agent
      </div>
    </div>` },

  dataeng: { title:'Data Engineering Agent', sub:'Telemetry Ingestion & Normalization · Streaming', body:`
    <div class="ds"><div class="ds-head">Role</div><div class="reasoning">Connects to Splunk Enterprise Security via MCP (Model Context Protocol) and makes enriched, CIM-normalised telemetry available to all downstream agents. It translates hunt hypotheses into SPL queries, exposes relevant data models and field extractions, and streams event context into the shared agent workspace so the RAA Supervisor Agent and Detection Logic Agent can operate on structured, hunt-ready data.</div></div>
    <div class="ds"><div class="ds-head">🔌 MCP Connection</div>
      <div style="display:flex;align-items:center;gap:8px;padding:6px 0 4px;">
        <span style="font-size:18px;">🟠</span>
        <div>
          <div style="font-weight:600;font-size:12px;">Splunk Enterprise Security</div>
          <div style="font-size:10px;color:var(--green);">MCP Server v2.1 · Connected · REST API</div>
        </div>
      </div>
      <div class="ioc-row" style="margin-top:4px;"><span class="ioc-t">Auth</span>Service account · TLS 1.3</div>
      <div class="ioc-row"><span class="ioc-t">Host</span>splunk-es.corp:8089</div>
      <div class="ioc-row"><span class="ioc-t">Role</span>hunt_agent_ro (read-only)</div>
    </div>
    <div class="ds"><div class="ds-head">Indices Available</div>
      <div class="ioc-row"><span class="ioc-t">IDX</span><code style="font-size:10px;color:var(--blue);">main</code> — general endpoint &amp; system events</div>
      <div class="ioc-row"><span class="ioc-t">IDX</span><code style="font-size:10px;color:var(--blue);">security</code> — Windows Security Event Log</div>
      <div class="ioc-row"><span class="ioc-t">IDX</span><code style="font-size:10px;color:var(--blue);">windows</code> — Sysmon + WinEvent (4624, 4688, 7045)</div>
      <div class="ioc-row"><span class="ioc-t">IDX</span><code style="font-size:10px;color:var(--blue);">sysmon</code> — process create, network, registry</div>
      <div class="ioc-row"><span class="ioc-t">IDX</span><code style="font-size:10px;color:var(--blue);">network</code> — firewall flows, DNS, proxy logs</div>
    </div>
    <div class="ds"><div class="ds-head">CIM Data Models Exposed</div>
      <div class="ioc-row"><span class="ioc-t">DM</span>Authentication · Endpoint · Network Traffic · Intrusion Detection</div>
      <div style="font-size:10px;color:var(--muted);padding:4px 0 0 6px;">Agents query via <code style="color:var(--blue);">datamodel()</code> accelerated search</div>
    </div>
    <div class="ds"><div class="ds-head">Active SPL Context</div>
      <div style="background:rgba(0,0,0,.35);border-radius:5px;padding:8px;font-size:10px;font-family:monospace;color:#86efac;line-height:1.7;overflow-x:auto;">
        index=windows EventCode=4688<br>
        &nbsp;&nbsp;| eval cmdline=lower(CommandLine)<br>
        &nbsp;&nbsp;| where match(cmdline,"powershell|encoded|bypass")<br>
        &nbsp;&nbsp;| stats count by host,ParentProcessName,cmdline<br>
        <span style="color:var(--muted);">— feeding RAA Supervisor Agent · 342 events/min</span>
      </div>
    </div>
    <div class="ds"><div class="ds-head">Normalisation Stats</div>
      <div class="kv-grid">
        <span class="kv-k">Events/min</span><span class="kv-v">342</span>
        <span class="kv-k">CIM Schema</span><span class="kv-v">Splunk CIM 5.x</span>
        <span class="kv-k">Field Coverage</span><span class="kv-v">97.1% mapped</span>
        <span class="kv-k">Drop rate</span><span class="kv-v">0.2% (malformed)</span>
      </div>
    </div>` },

  tradecraft: { title:'RAA Supervisor Agent', sub:'Reasoning Augmented Analytics · ALERTING', body:`
    <div class="ds"><div class="ds-head">Role</div><div class="reasoning">Applies reasoning-augmented analytics to score process behaviour against adversary tradecraft models. Specialises in two core detections: <b>command-line anomaly scoring</b> (flags unusual flag combinations, encoded payloads, LOLBin abuse) and <b>process chain anomaly</b> (detects unexpected parent-child relationships against a learned baseline). Outputs enriched hypotheses with confidence scores for the Orchestrator.</div></div>
    <div class="ds"><div class="ds-head">📊 Active RAA Analytics</div>
      <div class="ioc-row" style="flex-direction:column;align-items:flex-start;gap:2px;">
        <div style="display:flex;align-items:center;gap:7px;"><span class="chip chip-red" style="font-size:9px;">ALERTING</span><span style="font-size:11px;font-weight:600;color:var(--text);">Process Chain Anomaly</span></div>
        <div style="font-size:10px;color:var(--muted);padding-left:6px;">↳ Detects unexpected parent-child relationships against learned baseline · 3 hits this hunt</div>
      </div>
      <div class="ioc-row" style="flex-direction:column;align-items:flex-start;gap:2px;margin-top:6px;">
        <div style="display:flex;align-items:center;gap:7px;"><span class="chip chip-yellow" style="font-size:9px;">ACTIVE</span><span style="font-size:11px;font-weight:600;color:var(--text);">Command-Line Anomaly Scoring</span></div>
        <div style="font-size:10px;color:var(--muted);padding-left:6px;">↳ Flags unusual flag combos, encoded payloads, LOLBin abuse · scoring threshold 75+</div>
      </div>
      <div class="ioc-row" style="flex-direction:column;align-items:flex-start;gap:2px;margin-top:6px;">
        <div style="display:flex;align-items:center;gap:7px;"><span class="chip chip-green" style="font-size:9px;">ACTIVE</span><span style="font-size:11px;font-weight:600;color:var(--text);">Network Behaviour Baseline</span></div>
        <div style="font-size:10px;color:var(--muted);padding-left:6px;">↳ East-west flow deviation scoring against 30-day rolling baseline · 0 hits this hunt</div>
      </div>
    </div>
` },

  detection: { title:'Detection Logic Agent', sub:'Hunting Rule Creation · Active', body:`
    <div class="ds"><div class="ds-head">Role</div><div class="reasoning">Translates hypotheses and RAA Supervisor Agent outputs into executable detection rules. Generates multi-format output: KQL for Microsoft Sentinel, Sigma for SIEM-agnostic distribution, Splunk SPL, and YARA-L for endpoint platforms. Rules are automatically passed to the Rule Validation Agent before deployment.</div></div>
    <div class="ds"><div class="ds-head">Output Formats</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;font-size:11px;">
        <span class="chip chip-blue">KQL</span><span class="chip chip-indigo">Sigma</span><span class="chip chip-gray">Splunk SPL</span><span class="chip chip-gray">YARA-L</span>
      </div>
    </div>` },

  validation: { title:'Rule Validation Agent', sub:'Detection Rule QA & Testing · Testing', body:`
    <div class="ds"><div class="ds-head">Role</div><div class="reasoning">Receives draft detection rules from the Detection Logic Agent and runs a multi-stage validation pipeline: syntactic checks, back-testing against historical labelled event data, false-positive rate estimation, and a coverage gap analysis against the active MITRE technique list. Only rules passing all gates are approved for SIEM deployment.</div></div>
    <div class="ds"><div class="ds-head">Validation Gates</div>
      <div style="display:flex;flex-direction:column;gap:4px;font-size:11px;color:var(--sub);">
        <div>① Syntax check &amp; schema validation</div>
        <div>② Back-test against 30-day labelled dataset</div>
        <div>③ FP rate threshold &lt; 5%</div>
        <div>④ MITRE coverage gap analysis</div>
        <div>⑤ Orchestrator approval → SIEM push</div>
      </div>
    </div>` }
};

function openAgentDrawer(key, row) {
  const d = agentData[key]; if (!d) return;
  document.getElementById('drw-title').textContent = d.title;
  document.getElementById('drw-sub').textContent = d.sub;
  document.getElementById('drw-body').innerHTML = d.body;
  document.getElementById('drawer').classList.add('open');
  if (row) {
    document.querySelectorAll('.agent-row').forEach(r => r.classList.remove('sel'));
    row.classList.add('sel');
  }
}

function openHuntDrawer(id) {
  document.getElementById('drw-title').textContent = id;
  document.getElementById('drw-sub').textContent = 'Threat Hunt Details';
  const active = id === 'TH-2026-041';
  document.getElementById('drw-body').innerHTML = `
    <div class="ds"><div class="ds-head">Hunt Info</div>
    <div class="kv-grid">
      <span class="kv-k">Hunt ID</span><span class="kv-v">${id}</span>
      <span class="kv-k">Status</span><span class="kv-v" style="color:${active?'var(--blue)':'var(--green)'}">${active?'● Active':'✓ Complete'}</span>
      <span class="kv-k">CTI Source</span><span class="kv-v">CISA AA24-038A</span>
      <span class="kv-k">Analyst</span><span class="kv-v">jdoe</span>
      <span class="kv-k">LOCK Stage</span><span class="kv-v">${active?'Observe → Check':'Keep (closed)'}</span>
    </div></div>
    ${active ? `<button class="btn btn-primary" style="width:100%;margin-top:6px;" onclick="goTab('observe',document.querySelectorAll('.nav-tab')[1])">Open in Observe →</button>` : ''}`;
  document.getElementById('drawer').classList.add('open');
}

function closeDrawer() { document.getElementById('drawer').classList.remove('open'); }

// ── Chat ──
function toggleChat() { document.getElementById('chat-panel').classList.toggle('open'); }
const replies = {
  lsass: "LSASS memory access on WIN-DC01 by svchost (PID 3812) is critical. Pattern matches Mimikatz. Recommend isolating WIN-DC01 immediately and capturing a memory dump.",
  lateral: "H-01 confirmed — PsExec lateral movement across 14 hosts from 10.14.22.88. jsmith account active at 09:38 UTC outside business hours.",
  hyp: "3 hypotheses generated from Volt Typhoon CTI. H-01 (PsExec) is highest confidence — confirmed. H-02 (LSASS/Kerberoasting) likely. H-03 (CS beacon) under investigation.",
  kql: "For C2 detection:\n\nNetworkEvents\n| where RemoteIP == '185.220.101.47'\n| summarize count() by bin(TimeGenerated, 1m)\n| where count_ > 1",
  default: "Based on TH-2026-041, the attack chain is: Valid Accounts (T1078) → PsExec Lateral Movement (T1570) → Credential Dump (T1003) → C2 Beacon (T1071) → Persistence (T1547). TTPs match Volt Typhoon / CISA AA24-038A."
};
function sendMsg() {
  const inp = document.getElementById('chat-input');
  const val = inp.value.trim(); if (!val) return;
  const msgs = document.getElementById('chat-msgs');
  msgs.innerHTML += `<div class="msg user"><div class="msg-av">👤</div><div class="msg-bubble">${val}</div></div>`;
  msgs.innerHTML += `<div class="msg ai" id="typing-row"><div class="msg-av">⚡</div><div class="msg-bubble"><span class="typing"><span></span><span></span><span></span></span></div></div>`;
  inp.value = ''; msgs.scrollTop = 9999;
  const lc = val.toLowerCase();
  const r = lc.includes('lsass')||lc.includes('mimikatz') ? replies.lsass
    : lc.includes('lateral')||lc.includes('psexec') ? replies.lateral
    : lc.includes('hyp') ? replies.hyp
    : lc.includes('kql')||lc.includes('query') ? replies.kql
    : replies.default;
  setTimeout(() => {
    document.getElementById('typing-row').innerHTML = `<div class="msg-av">⚡</div><div class="msg-bubble">${r.replace(/\n/g,'<br>')}</div>`;
    msgs.scrollTop = 9999;
  }, 850);
}

// ── Modal ──
function openModal() { document.getElementById('modal').classList.add('open'); }
function closeModal() { document.getElementById('modal').classList.remove('open'); }
function launchHunt() { closeModal(); openHunt('TH-2026-041'); }

// ── Similar Hunts ──
const similarHunts = {
  '041': [
    {
      id: 'TH-2026-038', title: 'Volt Typhoon — Living off the Land', date: '2026-02-14',
      score: 91, actor: 'Volt Typhoon',
      sharedTtps: ['T1078.002','T1570','T1071.001'],
      reusableRules: 5, confirmedFindings: 4,
      outcome: 'Confirmed lateral movement across 9 hosts. PsExec SPL rule still deployed.',
      adapt: ['PsExec lateral movement SPL (tuned baseline)', 'Off-hours service account logon rule', 'ADMIN$ share + service creation rule']
    },
    {
      id: 'TH-2026-035', title: 'APT41 — Dual-Use Credential Theft', date: '2026-01-08',
      score: 74, actor: 'APT41',
      sharedTtps: ['T1003.001','T1558.003'],
      reusableRules: 3, confirmedFindings: 2,
      outcome: 'LSASS dump confirmed on 2 DCs. Kerberoasting SPL rule tuned to reduce FP rate.',
      adapt: ['LSASS handle access rule (non-system)', 'Kerberoasting TGS-REQ volume rule (tuned)']
    },
    {
      id: 'TH-2025-091', title: 'FANCY BEAR — Persistence & C2', date: '2025-11-22',
      score: 58, actor: 'FANCY BEAR',
      sharedTtps: ['T1547.001','T1053.005'],
      reusableRules: 2, confirmedFindings: 1,
      outcome: 'Registry run key persistence confirmed. Scheduled task rule flagged 3 FPs from software deployment.',
      adapt: ['Registry run key persistence rule', 'Scheduled task exclusion list (software deployment FP filter)']
    }
  ],
  '040': [
    {
      id: 'TH-2025-088', title: 'SCATTERED SPIDER — MFA Bypass', date: '2025-10-31',
      score: 83, actor: 'SCATTERED SPIDER',
      sharedTtps: ['T1566.001','T1078.004'],
      reusableRules: 4, confirmedFindings: 3,
      outcome: 'MFA fatigue attack confirmed. Cloud account takeover rule still active.',
      adapt: ['MFA push fatigue detection', 'Impossible travel logon rule', 'Cloud storage access anomaly']
    }
  ],
  '039': [
    {
      id: 'TH-2025-079', title: 'Lazarus — Supply Chain Staging', date: '2025-09-03',
      score: 78, actor: 'Lazarus Group',
      sharedTtps: ['T1195.002','T1574.002'],
      reusableRules: 3, confirmedFindings: 2,
      outcome: 'DLL sideloading confirmed via signed binary. Supply chain rule deployed.',
      adapt: ['DLL sideloading via signed binary', 'Unsigned module load from temp path']
    }
  ]
};

function renderSimilarHunts(huntId) {
  const list = document.getElementById('sim-hunt-list');
  const matches = similarHunts[huntId] || [];
  document.getElementById('sim-hunt-count').textContent = matches.length + ' match' + (matches.length !== 1 ? 'es' : '');
  if (!matches.length) {
    list.innerHTML = '<div style="font-size:11px;color:var(--muted);text-align:center;padding:10px 0;">No similar hunts found.</div>';
    return;
  }
  list.innerHTML = matches.map(h => `
    <div class="sim-hunt">
      <div class="sim-hunt-head">
        <span class="chip chip-blue" style="font-size:10px;">${h.id}</span>
        <span style="font-size:11px;font-weight:600;flex:1;">${h.title}</span>
        <span class="chip ${h.score>=80?'chip-green':h.score>=65?'chip-yellow':'chip-gray'}" style="font-size:10px;">${h.score}% match</span>
      </div>
      <div style="font-size:10px;color:var(--muted);">${h.date} · ${h.actor}</div>
      <div class="sim-hunt-ttps">${h.sharedTtps.map(t=>`<span class="chip chip-indigo" style="font-size:9px;padding:1px 5px;">${t}</span>`).join('')}</div>
      <div style="font-size:10px;color:var(--sub);line-height:1.5;margin-top:2px;">${h.outcome}</div>
      <div class="sim-hunt-adapt">
        <div class="adapt-stat"><b>${h.reusableRules}</b>reusable rules</div>
        <div class="adapt-stat"><b>${h.confirmedFindings}</b>prior findings</div>
      </div>
      <button class="btn btn-outline btn-sm" style="margin-top:2px;" onclick="adaptHunt('${h.id}')">Adapt to current hunt →</button>
    </div>`).join('');
}

function adaptHunt(id) {
  const all = Object.values(similarHunts).flat();
  const h = all.find(x => x.id === id);
  if (!h) return;
  document.getElementById('drw-title').textContent = '🔁 Adapting from ' + h.id;
  document.getElementById('drw-sub').textContent = h.title;
  document.getElementById('drw-body').innerHTML =
    `<div style="display:flex;flex-direction:column;gap:10px;">
      <div class="info-bar"><span class="ib-icon">💡</span><span>The following rules from <b>${h.id}</b> overlap with the current hunt. Shared TTPs: ${h.sharedTtps.map(t=>`<b>${t}</b>`).join(', ')}.</span></div>
      <div class="ds-head" style="margin-top:4px;">Rules to adapt</div>
      ${h.adapt.map(r=>`
        <div style="display:flex;align-items:center;gap:9px;background:var(--s2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 11px;">
          <span style="font-size:13px;">⚙️</span>
          <span style="font-size:12px;flex:1;">${r}</span>
          <button class="btn btn-primary btn-sm" onclick="showToast('Rule queued in Check tab')">Add</button>
        </div>`).join('')}
      <div class="ds-head" style="margin-top:4px;">Previous outcome</div>
      <div class="reasoning">${h.outcome}</div>
      <div class="ds-head" style="margin-top:4px;">Prior findings</div>
      <div style="display:flex;gap:8px;">
        <div class="adapt-stat" style="flex:1;"><b>${h.reusableRules}</b>reusable rules</div>
        <div class="adapt-stat" style="flex:1;"><b>${h.confirmedFindings}</b>confirmed findings</div>
      </div>
    </div>`;
  document.getElementById('drawer').classList.add('open');
}

function showToast(msg) {
  let t = document.getElementById('toast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'toast';
    t.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--s3);border:1px solid var(--border2);border-radius:var(--radius-sm);padding:8px 18px;font-size:12px;color:var(--text);z-index:999;box-shadow:0 4px 20px rgba(0,0,0,.4);pointer-events:none;transition:opacity .3s;';
    document.body.appendChild(t);
  }
  t.textContent = '✓ ' + msg;
  t.style.opacity = '1';
  clearTimeout(t._to);
  t._to = setTimeout(() => t.style.opacity = '0', 2200);
}

// ── Learn — Past Hunt Memory sidebar ──
function renderLearnPastHunts() {
  const list = document.getElementById('learn-past-list');
  const matches = similarHunts['041'] || [];
  document.getElementById('learn-sim-count').textContent = matches.length + ' recalled';
  list.innerHTML = matches.map(h => {
    const noteKey = h.id.slice(-3);
    const notes = huntNotes[noteKey] || [];
    const top = notes[0];
    const noteHTML = top ? (() => {
      const u = users[top.author] || users.alice;
      const preview = top.text.length > 130 ? top.text.slice(0, 127) + '…' : top.text;
      return `<div style="background:var(--s3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 9px;margin-top:5px;">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
          <div class="user-av" style="width:18px;height:18px;font-size:8px;flex-shrink:0;background:${u.bg};color:${u.color};">${u.initials}</div>
          <span style="font-size:10px;font-weight:600;color:var(--text);">${u.name}</span>
          <span style="font-size:9px;color:var(--muted);">${top.ts}</span>
          ${notes.length > 1 ? `<span style="font-size:9px;color:var(--muted);margin-left:auto;">+${notes.length - 1} more</span>` : ''}
        </div>
        <div style="font-size:10px;color:var(--sub);line-height:1.5;font-style:italic;">"${preview}"</div>
      </div>`;
    })() : '';
    return `
    <div class="sim-hunt">
      <div class="sim-hunt-head">
        <span class="chip chip-blue" style="font-size:10px;">${h.id}</span>
        <span style="font-size:11px;font-weight:600;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${h.title}</span>
        <span class="chip ${h.score>=80?'chip-green':h.score>=65?'chip-yellow':'chip-gray'}" style="font-size:10px;flex-shrink:0;">${h.score}%</span>
      </div>
      <div class="sim-hunt-ttps">${h.sharedTtps.map(t => `<span class="chip chip-indigo" style="font-size:9px;padding:1px 5px;">${t}</span>`).join('')}</div>
      <div style="display:flex;gap:10px;margin-top:3px;font-size:10px;color:var(--sub);"><span><b>${h.confirmedFindings}</b> confirmed findings</span><span><b>${h.reusableRules}</b> rules deployed</span></div>
      <div style="font-size:10px;color:var(--muted);margin-top:3px;line-height:1.4;">${h.outcome}</div>
      ${noteHTML}
    </div>`;
  }).join('');
}

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
  const d = observeData[id];
  const main = document.getElementById('obs-main-body');
  const side = document.getElementById('obs-side-body');
  if (!main || !side) return;
  if (!d) {
    main.innerHTML = `<div class="info-bar"><span class="ib-icon">ℹ️</span><span>No observe profile available for this hunt yet.</span></div>`;
    side.innerHTML = '';
    return;
  }
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

// ── Hunt Report ──
function renderHuntReport(id) {
  const d = keepData[id];
  if (!d || !d.report) return;
  const r = d.report;
  const lock = d.lock;
  const ttpFilter = activeKeepTTP; // read current TTP scope

  const chip = document.getElementById('report-status-chip');
  chip.textContent = r.status;
  chip.className = 'chip ' + r.statusClass;

  // Filtered findings for this TTP scope
  const scopedFindings = ttpFilter === 'all'
    ? d.findings
    : d.findings.filter(f => extractTTP(f.meta) === ttpFilter);
  const scopedCrits = scopedFindings.filter(f => f.sev === 'c').length;
  const scopedHighs = scopedFindings.filter(f => f.sev === 'h').length;

  // Update collapsed summary
  const rs = document.getElementById('report-summary');
  if (rs) rs.textContent = ttpFilter === 'all'
    ? `${d.criticals} Critical · ${d.highs} High · ${r.status}`
    : `${ttpFilter} · ${scopedCrits} Critical · ${scopedHighs} High`;

  const u = users[d.createdBy] || {};

  const huntTitles = {
    '041': 'APT29 Lateral Movement & Credential Harvesting — Corp Domain',
    '040': 'Ransomware Pre-cursor BEC Activity — Finance Segment',
    '039': 'Supply Chain Compromise Indicators — DevOps Pipeline',
  };

  const ri = (items) => items.map(i =>
    `<div class="report-lock-item ${i.cls}">${i.text}</div>`
  ).join('');

  // L — unchanged (hunt-level context always relevant)
  const lItems = [{ cls: 'ri-blue', text: lock.l }];

  // O — show only findings in the current TTP scope
  const critFindings = scopedFindings.filter(f => f.sev === 'c');
  const oItems = [{ cls: 'ri-blue', text: lock.o }];
  critFindings.slice(0, 3).forEach(f => oItems.push({ cls: 'ri-red', text: f.title }));
  if (scopedHighs > 0) oItems.push({ cls: 'ri-yellow',
    text: `+${scopedHighs} High severity finding${scopedHighs > 1 ? 's' : ''}${ttpFilter !== 'all' ? ' for ' + ttpFilter : ' also recorded'}`
  });
  if (ttpFilter !== 'all' && !scopedFindings.length) {
    oItems.push({ cls: 'ri-yellow', text: `No findings recorded for ${ttpFilter} in this hunt.` });
  }

  // C — unchanged
  const raaInfo = lock.raa;
  const raaItem = raaInfo
    ? { cls: raaInfo.relevant && !raaInfo.partial ? 'ri-green' : 'ri-yellow', text: raaInfo.note }
    : { cls: 'ri-yellow', text: 'RAA: no data recorded' };
  const cItems = [
    { cls: 'ri-blue', text: lock.c },
    raaItem,
    ...r.impact.map(i => ({ cls: 'ri-blue', text: `${i.val} ${i.lbl}` })),
  ];

  // K — filter recommendations that mention the active TTP; fall back to all if none match
  let recPool = r.recommendations;
  if (ttpFilter !== 'all') {
    const matched = recPool.filter(rec => rec.includes(ttpFilter) || rec.replace(/<[^>]+>/g,'').toLowerCase().includes(ttpFilter.toLowerCase()));
    if (matched.length) recPool = matched;
  }
  const kItems = recPool.slice(0, 4).map(rec => ({
    cls: 'ri-green', text: rec.replace(/<[^>]+>/g, '')
  }));

  // TTP filter banner — shown when scoped to a single TTP
  const ttpBanner = ttpFilter !== 'all' ? `
    <div style="display:flex;align-items:center;gap:8px;padding:6px 14px;background:rgba(99,102,241,.07);border-bottom:1px solid rgba(99,102,241,.18);">
      <span style="font-size:10px;color:var(--indigo);">🔍 Filtered to</span>
      <span class="chip chip-indigo" style="font-size:10px;">${ttpFilter}</span>
      <span style="font-size:10px;color:var(--sub);">${ttpShortName(ttpFilter) || ''}</span>
      <span style="margin-left:auto;font-size:10px;color:var(--muted);">${scopedFindings.length} finding${scopedFindings.length!==1?'s':''} · ${scopedCrits} Critical · ${scopedHighs} High</span>
    </div>` : '';

  // Title: show TTP name when filtered, hunt title otherwise
  const reportTitle = ttpFilter !== 'all'
    ? `<span style="font-size:12px;font-weight:700;color:var(--indigo);font-family:monospace;">${ttpFilter}</span>
       <span style="font-size:10px;color:var(--muted);">·</span>
       <span style="font-size:11px;color:var(--sub);">${ttpShortName(ttpFilter) || huntTitles[id] || d.title}</span>`
    : `<span style="font-size:12px;font-weight:700;color:var(--text);font-family:monospace;">${d.title}</span>
       <span style="font-size:10px;color:var(--muted);">·</span>
       <span style="font-size:11px;color:var(--sub);">${huntTitles[id] || d.title}</span>`;

  document.getElementById('report-doc-body').innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;border-bottom:1px solid var(--border);background:rgba(0,0,0,.18);flex-wrap:wrap;border-radius:0;">
      ${reportTitle}
      <div style="margin-left:auto;display:flex;gap:5px;flex-wrap:wrap;">
        <span class="chip chip-red" style="font-size:10px;">${scopedCrits} Critical</span>
        <span class="chip chip-yellow" style="font-size:10px;">${scopedHighs} High</span>
        <span class="chip ${r.statusClass}" style="font-size:10px;">${r.status}</span>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:8px;padding:5px 14px 6px;border-bottom:1px solid var(--border);background:rgba(0,0,0,.08);">
      <span style="font-size:10px;color:var(--muted);">👤 ${u.name || d.createdBy}${u.role ? ' · ' + u.role : ''}</span>
      <span style="color:var(--border2);">·</span>
      <span style="font-size:10px;color:var(--muted);">🗓 ${d.createdAt}</span>
    </div>
    ${ttpBanner}
    <div class="report-lock-grid">
      <div class="report-lock-cell">
        <div class="lock-cell-head"><span class="lock-letter lock-l">L</span><span class="lock-cell-label">Learn</span></div>
        <div class="report-lock-items">${ri(lItems)}</div>
      </div>
      <div class="report-lock-cell">
        <div class="lock-cell-head"><span class="lock-letter lock-o">O</span><span class="lock-cell-label">Observe</span></div>
        <div class="report-lock-items">${ri(oItems)}</div>
      </div>
      <div class="report-lock-cell">
        <div class="lock-cell-head"><span class="lock-letter lock-c">C</span><span class="lock-cell-label">Check</span></div>
        <div class="report-lock-items">${ri(cItems)}</div>
      </div>
      <div class="report-lock-cell">
        <div class="lock-cell-head"><span class="lock-letter lock-k">K</span><span class="lock-cell-label">Keep</span></div>
        <div class="report-lock-items">${ri(kItems)}</div>
      </div>
    </div>
  `;
}

// ── Hunt Pivot ──
function renderHuntPivot(id) {
  const d = keepData[id];
  const el = document.getElementById('pivot-card-body');
  if (!d || !d.pivot || !el) return;
  const p = d.pivot;
  const techChips = p.techniques.map(t => `<span class="chip chip-gray" style="font-size:10px;">${t}</span>`).join('');
  const seedHTML = p.seedData.map(s => `<div class="report-rec-item" style="font-size:11px;">📎 ${s}</div>`).join('');
  el.innerHTML = `
    <div style="display:flex;flex-direction:column;gap:10px;">
      <div class="info-bar" style="background:rgba(99,102,241,.06);border-color:rgba(99,102,241,.2);"><span class="ib-icon">🔀</span><span>A completed hunt is a new starting point. The agent identified an unresolved thread from this hunt's findings that warrants a follow-on investigation — seeding the next Learn stage automatically.</span></div>
      <div>
        <div class="label" style="margin-bottom:5px;">Proposed Next Hunt — <span style="color:var(--blue);font-weight:600;">${p.huntId}</span></div>
        <div style="font-size:12px;color:var(--sub);line-height:1.6;">${p.hypothesis}</div>
      </div>
      <div>
        <div class="label" style="margin-bottom:5px;">Techniques in scope</div>
        <div style="display:flex;flex-wrap:wrap;gap:5px;">${techChips}</div>
      </div>
      <div>
        <div class="label" style="margin-bottom:5px;">Agent rationale</div>
        <div style="font-size:11px;color:var(--sub);line-height:1.55;font-style:italic;">${p.rationale}</div>
      </div>
      <div>
        <div class="label" style="margin-bottom:5px;">Seed data for new hunt</div>
        ${seedHTML}
      </div>
      <div style="display:flex;gap:7px;justify-content:flex-end;">
        <button class="btn btn-outline btn-sm" style="font-size:11px;">↗ Preview Hypothesis</button>
        <button class="btn btn-primary btn-sm" style="font-size:11px;">→ Start ${p.huntId}</button>
      </div>
    </div>`;
}

// ════════════════════════════════════════
// CTI SENTENCE TAGGING SYSTEM
// ════════════════════════════════════════

// Key sentences per report — each TTP is traced back to one of these
const reportSentences = {
  'r1': [
    { id:'s01', text:'Volt Typhoon actors use valid administrator credentials to authenticate to internal systems, bypassing detection by operating as legitimate users with valid domain accounts (T1078.002).' },
    { id:'s02', text:'Actors have been observed using Living-off-the-Land techniques, leveraging built-in Windows tools such as PsExec, wmic, and netsh to move laterally and transfer tools across compromised hosts.' },
    { id:'s03', text:'The group uses PowerShell and scripting frameworks to stage and execute payloads in-memory, minimising creation of new executables on disk to evade endpoint detection.' },
    { id:'s04', text:'Credential access has been achieved through LSASS memory dumping using tools such as Mimikatz and comsvcs.dll, specifically targeting domain controller hosts.' },
    { id:'s05', text:'Kerberoasting has been observed — Service Principal Names (SPNs) are targeted to harvest service account password hashes offline for privilege escalation.' },
    { id:'s06', text:'Command and control is conducted over HTTPS using custom profiles designed to blend with legitimate web traffic; JA3 fingerprints match known Cobalt Strike malleable C2 profiles.' },
    { id:'s07', text:'Data is exfiltrated through the established C2 channel, avoiding dedicated exfiltration tools to minimise the forensic artefact footprint and reduce network anomaly signatures.' },
    { id:'s08', text:'Actors establish persistence via scheduled tasks and registry Run keys, using names that mimic legitimate software entries (e.g. MicrosoftEdgeUpdate) to blend with environment baseline.' },
  ],
  'r2': [
    { id:'s01', text:'APT41 gains initial access via supply chain compromise, inserting malicious code into trusted software build environments to distribute implants via legitimate update channels.' },
    { id:'s02', text:'The group executes payloads through PowerShell and WMI to run code in-memory, avoiding disk-based artefacts that would be detected by endpoint security tools.' },
    { id:'s03', text:'APT41 encrypts victim files and deletes Volume Shadow Copies to maximise ransomware impact and prevent recovery in financially motivated operations.' },
  ],
  'r3': [
    { id:'s01', text:'Lazarus Group compromised the 3CX software supply chain, inserting a malicious stage-2 payload into Windows and macOS desktop application builds distributed to customers.' },
    { id:'s02', text:'Persistence was achieved via registry Run keys and startup folder entries using names that blend with legitimate application auto-start entries.' },
  ],
};

// TTP → sentence mapping per report (which sentence justifies extracting this technique)
const ttpSentenceMap = {
  'r1': {
    'T1078.002': 's01',
    'T1570':     's02',
    'T1003.001': 's04',
    'T1558.003': 's05',
    'T1071.001': 's06',
    'T1547.001': 's08',
    'T1053.005': 's08',
    'T1041':     's07',
  },
  'r2': {
    'T1195.002': 's01',
    'T1059.001': 's02',
    'T1486':     's03',
  },
  'r3': {
    'T1195.002': 's01',
    'T1547.001': 's02',
  },
};

let activeReportId = 'r1'; // updated when user selects a report from the repo
let customTTPs = [];        // { id, technique, tactic, sentenceText, reportId }
let customHypotheses = [];  // { text, ttpId, sentenceText, reportId, num }

function getCurrentSentences() { return reportSentences[activeReportId] || []; }
function getCurrentTTPSentenceMap() { return ttpSentenceMap[activeReportId] || {}; }

// ── Sentence panel ──
function renderSentencePanel(reportId) {
  const panel = document.getElementById('sent-panel');
  const countEl = document.getElementById('sent-panel-count');
  const wrap = document.getElementById('sent-panel-wrap');
  if (!panel || !wrap) return;
  const sents = reportSentences[reportId] || [];
  const sentMap = ttpSentenceMap[reportId] || {};
  // Build reverse map: sentenceId → [TTP, …]
  const revMap = {};
  Object.entries(sentMap).forEach(([ttp, sid]) => {
    if (!revMap[sid]) revMap[sid] = [];
    revMap[sid].push(ttp);
  });
  panel.innerHTML = sents.map(s => {
    const ttps = revMap[s.id] || [];
    return `<div class="sent-item${ttps.length ? ' tagged' : ''}">
      <span class="sent-item-id">${s.id.toUpperCase()}</span>
      <div class="sent-item-body">
        <div class="sent-item-text">${s.text}</div>
        ${ttps.length ? `<div class="sent-item-ttps">${ttps.map(t => `<span class="chip chip-indigo" style="font-size:9px;padding:0 5px;" data-ttp="${t}">${t}</span>`).join('')}</div>` : ''}
      </div>
    </div>`;
  }).join('');
  if (countEl) countEl.textContent = sents.length + ' sentence' + (sents.length !== 1 ? 's' : '');
  wrap.style.display = '';
}

function toggleSentPanel() {
  const panel = document.getElementById('sent-panel');
  const btn = document.getElementById('sent-panel-toggle-btn');
  if (!panel) return;
  const showing = panel.style.display !== 'none';
  panel.style.display = showing ? 'none' : '';
  if (btn) btn.textContent = showing ? '▾ Show sentences' : '▴ Hide sentences';
}

// ── Custom TTP form ──
function populateSentenceDropdown(selId) {
  const sel = document.getElementById(selId);
  if (!sel) return;
  const sents = getCurrentSentences();
  sel.innerHTML = '<option value="">— select a sentence from the CTI report —</option>' +
    sents.map(s => `<option value="${s.id}">${s.id.toUpperCase()}: ${s.text.length > 72 ? s.text.substring(0,72) + '…' : s.text}</option>`).join('');
}

// ── TTP ID autocomplete ──
/* ════════════════════════════════════
   EVIDENCE LOCKER
════════════════════════════════════ */
let evidenceItems = [];

function toggleEvidenceDrawer() {
  document.getElementById('ev-drawer').classList.toggle('open');
}

function addEvidence() {
  const type = document.getElementById('ev-type').value;
  const sev  = document.getElementById('ev-sev').value;
  const ttp  = document.getElementById('ev-ttp').value.trim();
  const desc = document.getElementById('ev-desc').value.trim();
  if (!desc) { document.getElementById('ev-desc').focus(); return; }
  evidenceItems.unshift({ id: Date.now(), type, sev, ttp, desc,
    time: new Date().toLocaleTimeString('en-GB', { hour:'2-digit', minute:'2-digit' }) });
  document.getElementById('ev-desc').value = '';
  document.getElementById('ev-ttp').value  = '';
  renderEvidenceList();
}

function removeEvidence(id) {
  evidenceItems = evidenceItems.filter(e => e.id !== id);
  renderEvidenceList();
}

function renderEvidenceList() {
  const list  = document.getElementById('ev-list');
  const badge = document.getElementById('ev-badge');
  const chip  = document.getElementById('ev-count-chip');
  const n = evidenceItems.length;
  chip.textContent = n + (n === 1 ? ' item' : ' items');
  badge.textContent = n;
  n > 0 ? badge.classList.add('show') : badge.classList.remove('show');
  if (!n) {
    list.innerHTML = `<div class="ev-empty"><span style="font-size:30px;">🗂️</span><span>No evidence captured yet</span><span style="font-size:10px;">Log interesting findings, IOC hits, or suspicious hosts below</span></div>`;
    return;
  }
  const sevColor = { High:'var(--red)', Med:'var(--yellow)', Low:'var(--blue)', Info:'var(--muted)' };
  const typeIcon = { Host:'🖥', IOC:'🎯', Event:'📋', Note:'📝' };
  list.innerHTML = evidenceItems.map(e => `
    <div class="ev-item">
      <div class="ev-item-head">
        <span style="font-size:13px;">${typeIcon[e.type]||'📋'}</span>
        <span class="ev-item-type" style="color:${sevColor[e.sev]||'var(--muted)'};">${e.type}</span>
        <span class="chip chip-gray" style="font-size:9px;padding:1px 5px;">${e.sev}</span>
        ${e.ttp ? `<span style="font-family:monospace;font-size:9px;color:var(--indigo);background:rgba(99,102,241,.08);border:1px solid rgba(99,102,241,.18);border-radius:3px;padding:1px 5px;">${e.ttp}</span>` : ''}
        <span class="ev-item-time">${e.time}</span>
      </div>
      <div class="ev-item-desc">${e.desc}</div>
      <button class="ev-item-del" onclick="removeEvidence(${e.id})">✕</button>
    </div>`).join('');
}

/* ════════════════════════════════════
   HUNT HISTORY
════════════════════════════════════ */
function openHistoryModal() {
  document.getElementById('history-overlay').classList.add('open');
}
function closeHistoryModal() {
  document.getElementById('history-overlay').classList.remove('open');
}

function openReportModal() {
  document.getElementById('report-overlay').classList.add('open');
  buildReport();
}

function closeReportModal() {
  document.getElementById('report-overlay').classList.remove('open');
}

function buildReport() {
  const huntId    = document.getElementById('hd-id')?.textContent || 'TH-2026-041';
  const huntTitle = document.getElementById('hd-title')?.textContent || '—';
  const today     = new Date().toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' });
  document.getElementById('report-hunt-id').textContent = huntId;

  const evSection = evidenceItems.length
    ? evidenceItems.map(e => `<div class="report-row">
        <span class="chip chip-gray" style="font-size:9px;">${e.type}</span>
        <span class="chip chip-gray" style="font-size:9px;">${e.sev}</span>
        <span style="flex:1;font-size:11px;color:var(--sub);">${e.desc}</span>
        ${e.ttp ? `<span style="font-family:monospace;font-size:10px;color:var(--muted);">${e.ttp}</span>` : ''}
      </div>`).join('')
    : `<div style="font-size:11px;color:var(--muted);">No evidence captured during this hunt.</div>`;

  document.getElementById('report-body').innerHTML = `
    <div class="report-section">
      <div class="report-sh">Hunt Summary</div>
      <div class="report-kv"><span class="report-kv-k">Hunt ID</span><span class="report-kv-v">${huntId}</span></div>
      <div class="report-kv"><span class="report-kv-k">Title</span><span class="report-kv-v">${huntTitle}</span></div>
      <div class="report-kv"><span class="report-kv-k">Date</span><span class="report-kv-v">${today}</span></div>
      <div class="report-kv"><span class="report-kv-k">Threat Actor</span><span class="report-kv-v">APT29 (Volt Typhoon indicators)</span></div>
      <div class="report-kv"><span class="report-kv-k">CTI Source</span><span class="report-kv-v">CISA AA23-347A — APT29 Targets Critical Infrastructure</span></div>
      <div class="report-kv"><span class="report-kv-k">Environment</span><span class="report-kv-v">Splunk ES · Corp domain · index=sysmon, wineventlog, network</span></div>
      <div class="report-kv"><span class="report-kv-k">Status</span><span class="report-kv-v">Detection Logic complete — pending Check execution</span></div>
    </div>

    <div class="report-section">
      <div class="report-sh">TTPs Investigated (7)</div>
      <div class="report-row"><span class="chip chip-blue" style="font-size:9px;">T1053.005</span><span style="flex:1;">Scheduled Task Creation</span><span style="font-size:10px;color:var(--green);">New rule generated</span></div>
      <div class="report-row"><span class="chip chip-blue" style="font-size:9px;">T1547.001</span><span style="flex:1;">Registry Run Key Persistence</span><span style="font-size:10px;color:var(--green);">New rule generated</span></div>
      <div class="report-row"><span class="chip chip-yellow" style="font-size:9px;">T1558.003</span><span style="flex:1;">Kerberoasting — Anomalous TGS-REQ</span><span style="font-size:10px;color:var(--yellow);">New rule (RAA 0 hits)</span></div>
      <div class="report-row"><span class="chip chip-green" style="font-size:9px;">T1570</span><span style="flex:1;">Tool Transfer / PsExec</span><span style="font-size:10px;color:var(--muted);">Deferred to RAA · 59 hits</span></div>
      <div class="report-row"><span class="chip chip-green" style="font-size:9px;">T1078.002</span><span style="flex:1;">Valid Accounts — Domain</span><span style="font-size:10px;color:var(--muted);">Deferred to RAA · 59 hits</span></div>
      <div class="report-row"><span class="chip chip-green" style="font-size:9px;">T1003.001</span><span style="flex:1;">LSASS Memory Access</span><span style="font-size:10px;color:var(--muted);">Deferred to RAA · 3 hits</span></div>
      <div class="report-row"><span class="chip chip-gray" style="font-size:9px;">T1021.006</span><span style="flex:1;">WinRM Lateral Movement</span><span style="font-size:10px;color:var(--muted);">Skipped — no telemetry</span></div>
    </div>

    <div class="report-section">
      <div class="report-sh">Detection Rules Created (3)</div>
      <div class="report-rule-block">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
          <span class="chip chip-blue" style="font-size:9px;">T1053.005</span>
          <span style="font-weight:600;">Scheduled Task Creation via schtasks.exe</span>
        </div>
        <div style="color:var(--muted);font-size:10px;">index=sysmon EventCode=1 · SCCM/msiexec baseline exclusions · risk-scored HIGH/MED on interpreter parents</div>
      </div>
      <div class="report-rule-block">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
          <span class="chip chip-blue" style="font-size:9px;">T1547.001</span>
          <span style="font-weight:600;">Registry Run Key Persistence</span>
        </div>
        <div style="color:var(--muted);font-size:10px;">index=sysmon EventCode=13 · OneDrive/Teams/Chrome excluded · HKLM vs HKCU hive differentiation</div>
      </div>
      <div class="report-rule-block">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
          <span class="chip chip-yellow" style="font-size:9px;">T1558.003</span>
          <span style="font-weight:600;">Kerberoasting — Anomalous TGS-REQ Volume</span>
        </div>
        <div style="color:var(--muted);font-size:10px;">index=wineventlog EventCode=4769 EncryptionType=0x17 · >3 SPNs/user/5m · BackupExec/MSSQLSvc excluded</div>
      </div>
    </div>

    <div class="report-section">
      <div class="report-sh">RAA Deferred (3 TTPs — confirmed hits)</div>
      <div class="report-row"><span class="chip chip-green" style="font-size:9px;">T1570</span><span style="flex:1;">Anomalous Command Lines analytic</span><span style="font-size:10px;color:var(--green);">59 hits</span></div>
      <div class="report-row"><span class="chip chip-green" style="font-size:9px;">T1078.002</span><span style="flex:1;">Anomalous Command Lines analytic</span><span style="font-size:10px;color:var(--green);">59 hits</span></div>
      <div class="report-row"><span class="chip chip-green" style="font-size:9px;">T1003.001</span><span style="flex:1;">Anomalous Process Chains analytic</span><span style="font-size:10px;color:var(--green);">3 hits</span></div>
    </div>

    <div class="report-section">
      <div class="report-sh">Evidence Captured (${evidenceItems.length})</div>
      ${evSection}
    </div>

    <div class="report-section">
      <div class="report-sh">Recommendations</div>
      <div style="font-size:11px;color:var(--sub);display:flex;flex-direction:column;gap:6px;line-height:1.6;">
        <div>• Deploy 3 new correlation searches to Splunk ES, scoped to Corp domain.</div>
        <div>• Triage RAA hits for T1570 and T1078.002 (59 hits) — volume suggests potential active threat activity.</div>
        <div>• Investigate T1021.006 telemetry gap — WinRM events absent from current wineventlog configuration.</div>
        <div>• Schedule follow-up hunt in 2 weeks to validate rule efficacy and tune thresholds based on FP rate.</div>
      </div>
    </div>`;
}

function copyReport() {
  const text = document.getElementById('report-body').innerText;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById('copy-report-btn');
    const orig = btn.innerHTML;
    btn.innerHTML = '✓ Copied!';
    setTimeout(() => btn.innerHTML = orig, 1600);
  });
}

/* ════════════════════════════════════
   INLINE RULE TEST
════════════════════════════════════ */
const ruleTestData = {
  'rule-1': {
    execTime:'1.2s', count:14,
    cols:['_time','host','User','task_name','task_cmd','risk'],
    riskCol:5,
    rows:[
      ['14:32:07','CORP-WS-114','jsmith','svchost_update','C:\\Users\\jsmith\\AppData\\Temp\\upd.exe','HIGH'],
      ['14:28:41','CORP-WS-092','lchen','OneDriveSetup','C:\\Program Files\\OneDrive\\setup.exe','MED'],
      ['13:57:19','CORP-WS-114','jsmith','AdobeUpd','powershell.exe -enc JABzAD...','HIGH'],
      ['13:44:02','CORP-SRV-004','svc_deploy','deploy_task','cmd.exe /c deploy.bat','MED'],
    ]
  },
  'rule-2': {
    execTime:'0.9s', count:6,
    cols:['_time','host','User','hive','TargetObject','Details'],
    riskCol:-1,
    rows:[
      ['14:31:55','CORP-WS-114','jsmith','USER','HKCU\\...\\Run\\svcmon','C:\\Users\\jsmith\\AppData\\Local\\svcmon.exe'],
      ['14:29:12','CORP-WS-088','agarcia','USER','HKCU\\...\\Run\\updater','%TEMP%\\upd32.exe'],
      ['14:11:04','CORP-WS-114','SYSTEM','SYSTEM','HKLM\\...\\Run\\WinDef','C:\\Windows\\Temp\\wdf.exe'],
    ]
  },
  'rule-3': {
    execTime:'2.1s', count:3,
    cols:['_time','Account','src_ip','spn_count','risk'],
    riskCol:4,
    rows:[
      ['14:33:21','jsmith@CORP','10.10.14.22','11','CRITICAL'],
      ['14:33:21','jsmith@CORP','10.10.14.22','11','CRITICAL'],
      ['13:58:44','lchen@CORP','10.10.11.54','4','MED'],
    ]
  }
};

function runRuleTest(btn, ruleId) {
  const panel = document.getElementById('test-panel-' + ruleId);
  if (panel.classList.contains('open')) {
    panel.classList.remove('open');
    btn.innerHTML = '▶ Run Test';
    btn.classList.remove('running');
    return;
  }
  btn.classList.add('running');
  btn.innerHTML = '<span class="spin">⟳</span> Running…';
  const d = ruleTestData[ruleId];
  const riskClass = { CRITICAL:'rrc-crit', HIGH:'rrc-high', MED:'rrc-med' };
  setTimeout(() => {
    const rows = d.rows.map(row =>
      '<tr>' + row.map((cell, i) =>
        i === d.riskCol
          ? `<td><span class="rrc ${riskClass[cell]||''}">${cell}</span></td>`
          : `<td>${cell}</td>`
      ).join('') + '</tr>'
    ).join('');
    panel.innerHTML = `
      <div class="rtp-inner">
        <div class="rtp-meta">
          <span>⚡ <span class="vg">${d.count} events</span></span>
          <span>⏱ <span class="v">${d.execTime}</span></span>
          <span>📅 Last 7 days · all hosts</span>
          <span style="margin-left:auto;color:var(--green);font-weight:600;">● Live Splunk</span>
        </div>
        <div style="overflow-x:auto;">
          <table class="rr-table">
            <thead><tr>${d.cols.map(c=>`<th>${c}</th>`).join('')}</tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>`;
    panel.classList.add('open');
    btn.innerHTML = '■ Hide results';
    btn.classList.remove('running');
  }, 1400);
}

function toggleSchema(btn) {
  const panel = btn.nextElementSibling;
  const open = panel.classList.toggle('open');
  btn.classList.toggle('open', open);
  btn.querySelector('.ds-schema-arrow').textContent = open ? '›' : '›';
}

function onTTPIdInput(val) {
  const ac = document.getElementById('ctf-autocomplete');
  if (!ac) return;
  const q = val.trim().toUpperCase();
  if (!q) { ac.innerHTML = ''; ac.classList.remove('open'); return; }
  const matches = Object.entries(ttpInfo).filter(([id, info]) =>
    id.toUpperCase().includes(q) ||
    (info.name && info.name.toUpperCase().includes(q))
  ).slice(0, 8);
  if (!matches.length) { ac.innerHTML = ''; ac.classList.remove('open'); return; }
  ac.innerHTML = matches.map(([id, info]) =>
    `<div class="ttp-ac-item" onmousedown="selectTTPFromAutocomplete('${id}')">
      <div class="ttp-ac-id">${id}</div>
      <div class="ttp-ac-name">${info.name || ''}</div>
      <div class="ttp-ac-tactic">${info.tactic || ''}</div>
    </div>`
  ).join('');
  ac.classList.add('open');
}

function selectTTPFromAutocomplete(id) {
  const info = ttpInfo[id];
  const idInput = document.getElementById('ctf-id');
  const nameInput = document.getElementById('ctf-name');
  const tacticSel = document.getElementById('ctf-tactic');
  const ac = document.getElementById('ctf-autocomplete');
  if (idInput) idInput.value = id;
  if (nameInput && info) nameInput.value = info.name || '';
  if (tacticSel && info && info.tactic) {
    // Find matching option — exact then partial (handles compound tactics like 'Persistence / Execution')
    const tl = info.tactic.toLowerCase();
    const opts = tacticSel.options;
    let bestIdx = -1, bestScore = 0;
    for (let i = 0; i < opts.length; i++) {
      const ol = opts[i].text.toLowerCase();
      if (ol === tl) { bestIdx = i; break; }  // exact
      if (tl.includes(ol) && ol.length > bestScore) { bestScore = ol.length; bestIdx = i; }  // partial
    }
    if (bestIdx >= 0) tacticSel.selectedIndex = bestIdx;
  }
  if (ac) { ac.innerHTML = ''; ac.classList.remove('open'); }
}

function onTTPIdKey(e) {
  const ac = document.getElementById('ctf-autocomplete');
  if (!ac || !ac.classList.contains('open')) return;
  const items = ac.querySelectorAll('.ttp-ac-item');
  const cur = ac.querySelector('.ttp-ac-item.focused');
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    if (!cur) { items[0] && items[0].classList.add('focused'); }
    else {
      const next = cur.nextElementSibling;
      cur.classList.remove('focused');
      if (next) next.classList.add('focused'); else items[0] && items[0].classList.add('focused');
    }
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    if (cur) {
      const prev = cur.previousElementSibling;
      cur.classList.remove('focused');
      if (prev) prev.classList.add('focused'); else items[items.length-1] && items[items.length-1].classList.add('focused');
    }
  } else if (e.key === 'Enter') {
    if (cur) { e.preventDefault(); const id = cur.querySelector('.ttp-ac-id')?.textContent; if (id) selectTTPFromAutocomplete(id.trim()); }
  } else if (e.key === 'Escape') {
    ac.innerHTML = ''; ac.classList.remove('open');
  }
}

// Close autocomplete when clicking elsewhere
document.addEventListener('click', function(e) {
  if (!e.target.closest('#ctf-autocomplete') && e.target.id !== 'ctf-id') {
    const ac = document.getElementById('ctf-autocomplete');
    if (ac) { ac.innerHTML = ''; ac.classList.remove('open'); }
  }
});

// ── Hypothesis TTP → sentence auto-fill ──
function onHypTTPChange(ttpId) {
  const wrap = document.getElementById('chf-sentence-wrap');
  const disp = document.getElementById('chf-sentence-display');
  if (!wrap || !disp) return;
  if (!ttpId) { wrap.style.display = 'none'; disp.textContent = ''; return; }
  // Look up sentence from ttpSentenceMap for current report
  const sentMap = getCurrentTTPSentenceMap();
  const sentId = sentMap[ttpId];
  if (sentId) {
    const sents = getCurrentSentences();
    const s = sents.find(x => x.id === sentId);
    if (s) { disp.textContent = s.text; wrap.style.display = ''; return; }
  }
  // Look in customTTPs for a matching id with sentenceText
  const custom = customTTPs.find(t => t.id === ttpId && t.sentenceText);
  if (custom) { disp.textContent = custom.sentenceText; wrap.style.display = ''; return; }
  // TTP found but no sentence mapping
  wrap.style.display = 'none'; disp.textContent = '';
}

function toggleCustomTTPForm() {
  const form = document.getElementById('custom-ttp-form');
  const btn = document.getElementById('custom-ttp-toggle-btn');
  if (!form) return;
  const showing = form.style.display !== 'none';
  form.style.display = showing ? 'none' : '';
  if (btn) btn.textContent = showing ? '+ Add TTP' : '✕ Cancel';
  if (!showing) {
    document.getElementById('ctf-id').value = '';
    document.getElementById('ctf-name').value = '';
    document.getElementById('ctf-sentence').value = '';
    const ac = document.getElementById('ctf-autocomplete');
    if (ac) { ac.innerHTML = ''; ac.classList.remove('open'); }
  }
}

function addCustomTTP() {
  const id = document.getElementById('ctf-id')?.value.trim().toUpperCase();
  const name = document.getElementById('ctf-name')?.value.trim();
  const tactic = document.getElementById('ctf-tactic')?.value;
  const sentenceText = document.getElementById('ctf-sentence')?.value.trim();
  if (!id || !name) { alert('TTP ID and Technique Name are required.'); return; }
  customTTPs.push({ id, technique: name, tactic, sentenceText, reportId: activeReportId });
  document.getElementById('ctf-id').value = '';
  document.getElementById('ctf-name').value = '';
  document.getElementById('ctf-sentence').value = '';
  const ac = document.getElementById('ctf-autocomplete');
  if (ac) { ac.innerHTML = ''; ac.classList.remove('open'); }
  document.getElementById('custom-ttp-form').style.display = 'none';
  document.getElementById('custom-ttp-toggle-btn').textContent = '+ Add TTP';
  renderCustomTTPList();
  refreshHypTTPOptions();
}

function removeCustomTTP(i) {
  customTTPs.splice(i, 1);
  renderCustomTTPList();
  refreshHypTTPOptions();
}

function renderCustomTTPList() {
  const list = document.getElementById('custom-ttp-list');
  if (!list) return;
  if (!customTTPs.length) { list.style.display = 'none'; return; }
  list.style.display = '';
  list.innerHTML = `<div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);padding:8px 0 4px;border-top:1px solid rgba(59,130,246,.15);margin-top:8px;display:flex;align-items:center;gap:5px;"><span style="color:var(--blue);">✎</span> Your TTPs (${customTTPs.length})</div>` +
    customTTPs.map((t, i) => {
      const snippet = t.sentenceText ? (t.sentenceText.length > 60 ? t.sentenceText.substring(0,60) + '…' : t.sentenceText) : '';
      return `<div class="custom-ttp-row">
        <span class="ttp-id" data-ttp="${t.id}">${t.id}</span>
        <span style="flex:1;font-size:12px;color:var(--text);">${t.technique}</span>
        <span class="chip chip-gray" style="font-size:9px;">${t.tactic}</span>
        ${snippet ? `<span style="font-size:10px;color:var(--muted);font-style:italic;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${t.sentenceText.replace(/"/g,'&quot;')}">"${snippet}"</span>` : ''}
        <button style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:11px;padding:0 3px;line-height:1;" onclick="removeCustomTTP(${i})" title="Remove">✕</button>
      </div>`;
    }).join('');
}

// ── Custom Hypothesis form ──
function refreshHypTTPOptions() {
  const sel = document.getElementById('chf-ttp');
  if (!sel) return;
  const baseOpts = `<option value="">— select TTP —</option>
    <option value="T1078.002">T1078.002 · Valid Accounts: Domain</option>
    <option value="T1570">T1570 · Lateral Tool Transfer</option>
    <option value="T1003.001">T1003.001 · LSASS Memory</option>
    <option value="T1558.003">T1558.003 · Kerberoasting</option>
    <option value="T1071.001">T1071.001 · Web Protocols C2</option>
    <option value="T1547.001">T1547.001 · Registry Run Keys</option>
    <option value="T1053.005">T1053.005 · Scheduled Task</option>
    <option value="T1041">T1041 · Exfil Over C2 Channel</option>`;
  const customOpts = customTTPs.length
    ? `<optgroup label="── Custom TTPs ──">${customTTPs.map(t => `<option value="${t.id}">${t.id} · ${t.technique}</option>`).join('')}</optgroup>`
    : '';
  sel.innerHTML = baseOpts + customOpts;
}

function toggleCustomHypForm() {
  const form = document.getElementById('custom-hyp-form');
  const btn = document.getElementById('custom-hyp-toggle-btn');
  if (!form) return;
  const showing = form.style.display !== 'none';
  form.style.display = showing ? 'none' : '';
  if (btn) btn.textContent = showing ? '+ Add Hypothesis' : '✕ Cancel';
  if (!showing) {
    refreshHypTTPOptions();
    // Reset sentence display
    const wrap = document.getElementById('chf-sentence-wrap');
    const disp = document.getElementById('chf-sentence-display');
    if (wrap) wrap.style.display = 'none';
    if (disp) disp.textContent = '';
  }
}

function addCustomHyp() {
  const text = document.getElementById('chf-text')?.value.trim();
  const ttpId = document.getElementById('chf-ttp')?.value;
  const sentenceText = document.getElementById('chf-sentence-display')?.textContent.trim();
  if (!text) { alert('Please enter a hypothesis statement.'); return; }
  const num = 'H-C' + (customHypotheses.length + 1);
  customHypotheses.push({ text, ttpId, sentenceText, reportId: activeReportId, num });
  document.getElementById('chf-text').value = '';
  document.getElementById('chf-ttp').value = '';
  const wrap = document.getElementById('chf-sentence-wrap');
  const disp = document.getElementById('chf-sentence-display');
  if (wrap) wrap.style.display = 'none';
  if (disp) disp.textContent = '';
  document.getElementById('custom-hyp-form').style.display = 'none';
  document.getElementById('custom-hyp-toggle-btn').textContent = '+ Add Hypothesis';
  renderCustomHypotheses();
}

function removeCustomHyp(i) {
  customHypotheses.splice(i, 1);
  renderCustomHypotheses();
}

function renderCustomHypotheses() {
  const list = document.getElementById('custom-hyp-list');
  if (!list) return;
  if (!customHypotheses.length) { list.innerHTML = ''; return; }
  list.innerHTML = customHypotheses.map((h, i) => {
    const st = h.sentenceText || '';
    return `<div class="hyp-card custom-hyp-card" onclick="selHyp(this)">
      <div class="hyp-head">
        <span class="hyp-num">${h.num}</span>
        <div class="hyp-text">${h.text.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>
        <button style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:11px;padding:0 3px;flex-shrink:0;margin-left:4px;line-height:1;" onclick="event.stopPropagation();removeCustomHyp(${i})" title="Remove">✕</button>
      </div>
      <div class="hyp-meta">
        ${h.ttpId ? `<span class="chip chip-blue" style="font-size:10px;">${h.ttpId}</span>` : ''}
        <span class="chip chip-gray" style="font-size:10px;">Analyst defined</span>
      </div>
      ${st ? `<div class="hyp-rationale" style="border-left:2px solid rgba(99,102,241,.3);padding-left:7px;margin-top:4px;font-style:italic;">"${st.replace(/</g,'&lt;').replace(/>/g,'&gt;')}"</div>` : ''}
    </div>`;
  }).join('');
}

// ── Sentence tooltip IIFE ──
(function () {
  const tip = document.createElement('div');
  tip.id = 'sent-tooltip';
  document.body.appendChild(tip);

  function show(el) {
    const sid = el.dataset.sid;
    if (!sid) return;
    // Search all known sentence sets
    let found = null;
    for (const sents of Object.values(reportSentences)) {
      found = sents.find(x => x.id === sid);
      if (found) break;
    }
    if (!found) return;
    tip.innerHTML = `<div class="sent-tip-id">Sentence ${found.id.toUpperCase()}</div><div class="sent-tip-text">"${found.text}"</div>`;
    tip.style.display = 'block';
    reposition(el);
  }

  function hide() { tip.style.display = 'none'; }

  function reposition(el) {
    const W = 300, PAD = 8;
    const r = el.getBoundingClientRect();
    const h = tip.offsetHeight || 60;
    let top = r.top - h - PAD;
    if (top < PAD) top = r.bottom + PAD;
    let left = r.left + r.width / 2 - W / 2;
    if (left < PAD) left = PAD;
    if (left + W > window.innerWidth - PAD) left = window.innerWidth - W - PAD;
    tip.style.top  = top  + 'px';
    tip.style.left = left + 'px';
  }

  document.addEventListener('mouseover', e => {
    const el = e.target.closest('[data-sid]');
    if (el) show(el); else hide();
  });
  document.addEventListener('mouseout', e => {
    if (!e.relatedTarget || !e.relatedTarget.closest('[data-sid]')) hide();
  });
  document.addEventListener('scroll', hide, true);
})();

// ════════════════════════════════════════
// TTP TOOLTIP SYSTEM
// ════════════════════════════════════════
const ttpInfo = {
  'T1003':     { tactic: 'Credential Access', name: 'OS Credential Dumping', desc: 'Adversaries attempt to dump credentials to obtain account login material from the OS or software.' },
  'T1003.001': { tactic: 'Credential Access', name: 'LSASS Memory', desc: 'Adversaries access LSASS process memory to extract credentials. Common tools: Mimikatz, ProcDump. Detected via anomalous process handle access to lsass.exe with suspicious access masks (0x1fffff, 0x1410).' },
  'T1018':     { tactic: 'Discovery', name: 'Remote System Discovery', desc: 'Adversaries enumerate other systems on the network via ping sweeps, ARP, LDAP/AD queries, or net view.' },
  'T1021':     { tactic: 'Lateral Movement', name: 'Remote Services', desc: 'Adversaries use valid accounts to log into remote services (RDP, SMB, WinRM) to move laterally across the network.' },
  'T1027':     { tactic: 'Defense Evasion', name: 'Obfuscated Files or Information', desc: 'Adversaries encode, encrypt, or otherwise obfuscate artifacts to make detection more difficult.' },
  'T1041':     { tactic: 'Exfiltration', name: 'Exfiltration Over C2 Channel', desc: 'Adversaries steal data by exfiltrating it over an existing command-and-control channel, blending exfil with normal C2 traffic.' },
  'T1046':     { tactic: 'Discovery', name: 'Network Service Discovery', desc: 'Adversaries scan for services running on remote hosts, often via port scanning or protocol-specific probes.' },
  'T1053':     { tactic: 'Persistence / Execution', name: 'Scheduled Task / Job', desc: 'Adversaries abuse task scheduling to execute malicious code at initial access or on a recurring basis.' },
  'T1053.005': { tactic: 'Persistence / Execution', name: 'Scheduled Task', desc: 'Adversaries use Windows Task Scheduler to run arbitrary commands at logon or on a schedule, often for persistence.' },
  'T1059':     { tactic: 'Execution', name: 'Command and Scripting Interpreter', desc: 'Adversaries abuse command interpreters (cmd, PowerShell, WMI, Bash) to execute commands, scripts, or binaries.' },
  'T1071':     { tactic: 'Command & Control', name: 'Application Layer Protocol', desc: 'Adversaries communicate with C2 over standard application-layer protocols (HTTP, HTTPS, DNS) to blend with legitimate traffic.' },
  'T1071.001': { tactic: 'Command & Control', name: 'Web Protocols — C2', desc: 'Adversaries use HTTP/HTTPS to communicate with C2, often using malleable C2 profiles (e.g. Cobalt Strike) to mimic legitimate web traffic. Detected via JA3 fingerprints and beacon interval analysis.' },
  'T1078':     { tactic: 'Defense Evasion / Persistence', name: 'Valid Accounts', desc: 'Adversaries obtain and abuse credentials of existing accounts to bypass access controls and evade detection.' },
  'T1078.002': { tactic: 'Defense Evasion / Persistence', name: 'Valid Accounts: Domain Accounts', desc: 'Adversaries compromise domain accounts to authenticate across an Active Directory environment, enabling lateral movement and access to shared resources.' },
  'T1083':     { tactic: 'Discovery', name: 'File and Directory Discovery', desc: 'Adversaries enumerate files and directories to identify collection targets or understand the host environment layout.' },
  'T1135':     { tactic: 'Discovery', name: 'Network Share Discovery', desc: 'Adversaries enumerate shared drives or network shares on remote systems using net view, net share, or SMB enumeration.' },
  'T1547':     { tactic: 'Persistence', name: 'Boot or Logon Autostart Execution', desc: 'Adversaries modify autostart mechanisms (registry run keys, startup folders) to execute malware at boot or user logon.' },
  'T1547.001': { tactic: 'Persistence', name: 'Registry Run Keys / Startup Folder', desc: 'Adversaries add entries under HKCU or HKLM Run keys to execute malware automatically at user logon.' },
  'T1558':     { tactic: 'Credential Access', name: 'Steal or Forge Kerberos Tickets', desc: 'Adversaries steal or forge Kerberos tickets to gain unauthorized access to AD resources without valid plaintext credentials.' },
  'T1558.003': { tactic: 'Credential Access', name: 'Kerberoasting', desc: 'Adversaries request Kerberos service tickets (TGS) for accounts with registered SPNs, then crack them offline to obtain service account passwords. Detected via anomalous EventCode 4769 volume.' },
  'T1570':     { tactic: 'Lateral Movement', name: 'Lateral Tool Transfer', desc: 'Adversaries transfer tools between systems in a compromised environment using PsExec, WMI, SMB shares, or RDP clipboard. Detected via psexesvc.exe, wmic /node: remote execution patterns.' },
};

(function () {
  const tip = document.createElement('div');
  tip.id = 'ttp-tooltip';
  document.body.appendChild(tip);

  function show(el) {
    const id = el.dataset.ttp;
    const info = ttpInfo[id];
    if (!info) return;
    tip.innerHTML =
      `<div class="ttp-tip-tactic">${info.tactic}</div>` +
      `<div class="ttp-tip-id">${id}</div>` +
      `<div class="ttp-tip-name">${info.name}</div>` +
      `<div class="ttp-tip-desc">${info.desc}</div>`;
    tip.style.display = 'block';
    reposition(el);
  }

  function hide() { tip.style.display = 'none'; }

  function reposition(el) {
    const W = 250, PAD = 8;
    const r = el.getBoundingClientRect();
    const h = tip.offsetHeight;
    let top = r.top - h - PAD;
    if (top < PAD) top = r.bottom + PAD;
    let left = r.left + r.width / 2 - W / 2;
    if (left < PAD) left = PAD;
    if (left + W > window.innerWidth - PAD) left = window.innerWidth - W - PAD;
    tip.style.top  = top  + 'px';
    tip.style.left = left + 'px';
  }

  document.addEventListener('mouseover', e => {
    const el = e.target.closest('[data-ttp]');
    if (el) show(el); else hide();
  });
  document.addEventListener('mouseout', e => {
    if (!e.relatedTarget || !e.relatedTarget.closest('[data-ttp]')) hide();
  });
  document.addEventListener('scroll', hide, true);
})();

// ── Auto-tag static TTP chips and table cells ──
(function () {
  // .ttp-id cells in tables — text content IS the TTP ID
  document.querySelectorAll('.ttp-id').forEach(el => {
    const t = el.textContent.trim();
    if (ttpInfo[t]) el.dataset.ttp = t;
  });
  // Standalone chip spans whose full text content is a TTP ID
  document.querySelectorAll('.chip').forEach(el => {
    const t = el.textContent.trim();
    if (ttpInfo[t]) { el.dataset.ttp = t; el.style.cursor = 'default'; }
  });
})();

// ── Init Keep tab + user ──
renderKeepHunt('041');
renderHuntReport('041');
renderHuntPivot('041');
renderHuntObserve('041');
renderSimilarHunts('041');
renderLearnPastHunts();
renderPostingAs();
renderCheckSummary('h01', false);
renderQueryIterations('h01');
renderRAAResults('h01');

// ── Init repo list ──
renderRepo(repoData);

// ── Live progress ──
let rv = 67;
setInterval(() => {
  rv = Math.min(100, rv + Math.random() * .5);
  document.querySelectorAll('.pf-recon').forEach(e => e.style.width = rv + '%');
}, 1400);

// ════════════════════════════════════════
// ENVIRONMENT CONTEXT  (MCP tool)
// ════════════════════════════════════════
// envData + crownJewels — see kb/environment.js

// ── Render helpers ──
function renderEcOverview() {
  // Stats strip
  document.getElementById('ec-overview-stats').innerHTML = envData.stats.map(s => `
    <div class="stat-card c-${s.color}" style="padding:12px 14px;">
      <div class="label">${s.label}</div>
      <div class="val" style="font-size:22px;">${s.value}</div>
      <div class="note">${s.note}</div>
    </div>`).join('');

  // Domain info
  const d = envData.domain;
  document.getElementById('ec-domain-info').innerHTML = `
    <div class="ec-detail-grid" style="background:var(--s2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 12px;">
      <span class="ec-detail-k">Domain</span><span class="ec-detail-v">${d.name}</span>
      <span class="ec-detail-k">NetBIOS</span><span class="ec-detail-v">${d.netbios}</span>
      <span class="ec-detail-k">Forest</span><span class="ec-detail-v">${d.forest}</span>
      <span class="ec-detail-k">FL</span><span class="ec-detail-v plain">${d.functionalLevel}</span>
      <span class="ec-detail-k">DCs</span><span class="ec-detail-v plain">${d.dcs.join('<br>')}</span>
      <span class="ec-detail-k">Sites</span><span class="ec-detail-v plain">${d.sites.join('<br>')}</span>
      <span class="ec-detail-k">Trusts</span><span class="ec-detail-v plain">${d.trusts.join('<br>')}</span>
      <span class="ec-detail-k">AD Sync</span><span class="ec-detail-v plain">${d.adSync}</span>
    </div>`;

  // Anomalies
  const sevMap = { crit:['rb-tip-crit','🔴','crit'], high:['rb-tip-high','🟡','high'], med:['rb-tip-info','🔵','info'] };
  document.getElementById('ec-anomalies').innerHTML = envData.anomalies.map(a => {
    const [cls, icon, lbl] = sevMap[a.sev] || sevMap.med;
    return `<div class="rb-tip ${cls}" style="margin-bottom:6px;">
      <span class="rb-tip-icon">${icon}</span>
      <div class="rb-tip-body"><div class="rb-tip-text">${a.text}</div></div>
    </div>`;
  }).join('');
}

function renderEcSegments(filter) {
  const q = (filter || '').toLowerCase();
  const segs = q ? envData.segments.filter(s =>
    s.name.toLowerCase().includes(q) || s.cidr.includes(q) ||
    s.desc.toLowerCase().includes(q) || s.tags.some(t => t.toLowerCase().includes(q))
  ) : envData.segments;

  document.getElementById('ec-seg-grid').innerHTML = segs.map(s => `
    <div class="ec-seg-card sens-${s.sensitivity}">
      <div class="ec-seg-card-head">
        <span class="ec-seg-icon">${s.icon}</span>
        <div style="flex:1;min-width:0;">
          <div class="ec-seg-name">${s.name}</div>
          <div class="ec-seg-subnet">${s.cidr} · VLAN ${s.vlan}</div>
        </div>
        <span class="chip chip-${s.sensitivity==='critical'?'red':s.sensitivity==='high'?'yellow':s.sensitivity==='medium'?'blue':'green'}" style="font-size:10px;">${s.sensitivity}</span>
      </div>
      <div class="ec-seg-body">
        <div style="margin-bottom:6px;">${s.desc}</div>
        <div style="color:var(--muted);margin-bottom:3px;font-size:10px;">ACLs</div>
        ${s.acls.map(a => `<div style="font-size:10px;color:var(--sub);">› ${a}</div>`).join('')}
        <div class="ec-seg-tags">${s.tags.map(t => `<span class="chip chip-gray" style="font-size:10px;padding:1px 6px;">${t}</span>`).join('')}
          <span class="chip chip-gray" style="font-size:10px;padding:1px 6px;">${s.hosts} hosts</span></div>
      </div>
    </div>`).join('') || '<div style="color:var(--muted);font-size:12px;">No segments match filter.</div>';
}

let ecAssetFilter = '';
function renderEcAssets(filter) {
  ecAssetFilter = filter || '';
  const q = ecAssetFilter.toLowerCase();
  const assets = q ? envData.assets.filter(a =>
    a.hostname.toLowerCase().includes(q) || a.ip.includes(q) ||
    a.os.toLowerCase().includes(q) || a.role.includes(q) ||
    a.segment.toLowerCase().includes(q) || a.owner.toLowerCase().includes(q)
  ) : envData.assets;

  const roleLabel = { dc:'Domain Controller', srv:'Server', ws:'Workstation', net:'Network/Jump', sec:'Security' };
  const roleCls   = { dc:'ec-role-dc', srv:'ec-role-srv', ws:'ec-role-ws', net:'ec-role-net', sec:'ec-role-sec' };
  const statusDot = s => s === 'online'
    ? `<span style="color:var(--green);font-size:10px;font-weight:600;">● Online</span>`
    : `<span style="color:var(--red);font-size:10px;font-weight:600;">● Offline</span>`;

  document.getElementById('ec-asset-tbody').innerHTML = assets.map(a => `
    <tr>
      <td><span class="ec-hostname" onclick="showAssetDetail('${a.hostname}')">${a.hostname}</span></td>
      <td style="font-family:monospace;color:var(--sub);font-size:11px;">${a.ip}</td>
      <td><span class="ec-role-badge ${roleCls[a.role]}">${roleLabel[a.role]||a.role}</span></td>
      <td style="color:var(--sub);font-size:11px;">${a.os}</td>
      <td style="font-size:11px;color:var(--muted);">${a.segment}</td>
      <td style="font-size:11px;color:var(--sub);">${a.owner}</td>
      <td style="font-size:11px;color:var(--muted);">${a.lastSeen}</td>
      <td>${statusDot(a.status)}</td>
    </tr>`).join('') || '<tr><td colspan="8" style="color:var(--muted);text-align:center;padding:14px;">No assets match filter.</td></tr>';
}

function showAssetDetail(hostname) {
  const a = envData.assets.find(x => x.hostname === hostname);
  if (!a) return;
  const slot = document.getElementById('ec-asset-detail-slot');
  const roleLabel = { dc:'Domain Controller', srv:'Server', ws:'Workstation', net:'Network/Jump', sec:'Security' };
  slot.innerHTML = `
    <div class="ec-asset-detail" style="margin-bottom:12px;">
      <div class="ec-asset-detail-head">
        <span style="font-weight:700;font-size:13px;font-family:monospace;">${a.hostname}</span>
        <span style="font-family:monospace;font-size:11px;color:var(--indigo);">${a.ip}</span>
        <span style="font-size:11px;color:var(--muted);">· ${a.segment}</span>
        <button onclick="document.getElementById('ec-asset-detail-slot').innerHTML=''" style="margin-left:auto;background:none;border:none;color:var(--muted);cursor:pointer;font-size:12px;">✕</button>
      </div>
      <div class="ec-detail-grid">
        <span class="ec-detail-k">FQDN</span><span class="ec-detail-v">${a.details.fqdn}</span>
        <span class="ec-detail-k">MAC</span><span class="ec-detail-v">${a.details.mac}</span>
        <span class="ec-detail-k">CPU</span><span class="ec-detail-v plain">${a.details.cpu}</span>
        <span class="ec-detail-k">RAM</span><span class="ec-detail-v plain">${a.details.ram}</span>
        <span class="ec-detail-k">Disk</span><span class="ec-detail-v plain">${a.details.disk}</span>
        <span class="ec-detail-k">Uptime</span><span class="ec-detail-v plain">${a.details.uptime}</span>
        <span class="ec-detail-k">Sysmon</span><span class="ec-detail-v plain">${a.details.sysmon}</span>
        <span class="ec-detail-k">EDR</span><span class="ec-detail-v plain">${a.details.edr}</span>
        <span class="ec-detail-k">Last patch</span><span class="ec-detail-v plain">${a.details.patch}</span>
        <span class="ec-detail-k">Criticality</span><span class="ec-detail-v plain">${a.details.criticality}</span>
        <span class="ec-detail-k">Notes</span><span class="ec-detail-v plain" style="font-family:inherit;">${a.details.notes}</span>
      </div>
    </div>`;
  slot.scrollIntoView({ behavior:'smooth', block:'nearest' });
}

function renderEcAccounts(filter) {
  const q = (filter || '').toLowerCase();
  const accs = q ? envData.accounts.filter(a =>
    a.name.toLowerCase().includes(q) || a.type.toLowerCase().includes(q) ||
    a.groups.some(g => g.toLowerCase().includes(q)) || a.status.includes(q)
  ) : envData.accounts;

  const typeChip = t => t === 'Admin' ? 'chip-red' : t === 'Service' ? 'chip-yellow' : 'chip-blue';
  document.getElementById('ec-accounts-list').innerHTML = accs.map(a => `
    <div class="ec-acc-row">
      <div class="ec-acc-head">
        <span class="ec-acc-name">CORP\\${a.name}</span>
        <span class="chip ${typeChip(a.type)}" style="font-size:10px;">${a.type}</span>
        ${a.status === 'active'
          ? '<span class="chip chip-green" style="font-size:10px;">Active</span>'
          : '<span class="chip chip-gray" style="font-size:10px;">Disabled</span>'}
        <span style="font-size:10px;color:var(--muted);margin-left:auto;">Groups: ${a.groups.join(' · ')}</span>
      </div>
      <div class="ec-acc-body">
        <span class="ec-acc-k">Normal logon</span><span>${a.normal}</span>
        <span class="ec-acc-k">Last logon</span><span>${a.lastLogon}</span>
        <span class="ec-acc-k">Pwd age</span><span>${a.pwdAge}</span>
        <span class="ec-acc-k">MFA</span><span>${a.mfa}</span>
      </div>
      ${a.anomaly ? `<div class="ec-acc-anomaly"><span class="ec-acc-anomaly-icon">⚠️</span>${a.anomaly}</div>` : ''}
    </div>`).join('') || '<div style="color:var(--muted);font-size:12px;">No accounts match filter.</div>';
}

function renderEcTopology() {
  document.getElementById('ec-topo-map').innerHTML = envData.topology;
  document.getElementById('ec-infra-list').innerHTML = envData.infrastructure.map(i => `
    <div style="display:flex;align-items:center;gap:10px;padding:7px 10px;background:var(--s2);border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:6px;font-size:11px;">
      <span style="font-size:16px;flex-shrink:0;">${i.icon}</span>
      <div style="flex:1;">
        <span style="font-weight:700;">${i.name}</span>
        <span style="color:var(--muted);margin-left:8px;">${i.role}</span>
      </div>
      <span style="font-family:monospace;font-size:10px;color:var(--indigo);">${i.ip}</span>
      <span class="chip chip-${i.crit==='Critical'||i.crit==='Tier-0'?'red':i.crit==='High'?'yellow':'blue'}" style="font-size:10px;">${i.crit}</span>
    </div>`).join('');
}

// ── Crown Jewels ──
// crownJewels — see kb/environment.js

function renderCrownJewels() {
  const pane = document.getElementById('ec-pane-crownJewels');
  if (!pane) return;
  const expDot = (e) => `<span class="cj-exp-dot ${e}"></span>`;
  const expLabel = { high:'In current hunt scope', medium:'Indirectly exposed', low:'Not currently exposed' };
  const t0 = crownJewels.assets.filter(a=>a.tier===0);
  const t1 = crownJewels.assets.filter(a=>a.tier===1);
  const inScope = crownJewels.assets.filter(a=>a.exposure==='high'||a.exposure==='medium').length;
  pane.innerHTML = `
    <div class="cj-summary-strip">
      <div class="cj-sum-item"><div class="cj-sum-val" style="color:var(--red);">${t0.length}</div><div class="cj-sum-lbl">Tier-0 assets</div></div>
      <div class="cj-sum-item"><div class="cj-sum-val" style="color:var(--orange);">${t1.length}</div><div class="cj-sum-lbl">Tier-1 assets</div></div>
      <div class="cj-sum-item"><div class="cj-sum-val">${crownJewels.accounts.length}</div><div class="cj-sum-lbl">Critical accounts</div></div>
      <div class="cj-sum-item"><div class="cj-sum-val" style="color:var(--yellow);">${inScope}</div><div class="cj-sum-lbl">In hunt scope</div></div>
    </div>
    <div class="cj-section-head"><span style="color:var(--red);">●</span> Tier-0 — Domain-Level Crown Jewels</div>
    <div class="cj-grid">
      ${t0.map(a=>`
      <div class="cj-card tier0">
        <div class="cj-card-head">
          <span class="cj-icon">${a.icon}</span>
          <span class="cj-name">${a.name}</span>
          <span class="cj-tier-badge tier0">Tier-0</span>
        </div>
        <div class="cj-card-body">
          <div class="cj-role">${a.role}</div>
          <div class="cj-ip">${a.ip} · ${a.segment}</div>
          <div>
            <div class="cj-blast-lbl">Blast Radius</div>
            <div class="cj-blast">${a.blast}</div>
          </div>
          <div class="cj-exposure">
            ${expDot(a.exposure)}<span class="cj-exp-label">${expLabel[a.exposure]}</span>
            ${a.ttp ? `<span class="cj-exp-ttp" style="margin-left:auto;">${a.ttp}</span>` : ''}
          </div>
        </div>
      </div>`).join('')}
    </div>
    <div class="cj-section-head" style="margin-top:16px;"><span style="color:var(--orange);">●</span> Tier-1 — High-Value Infrastructure</div>
    <div class="cj-grid">
      ${t1.map(a=>`
      <div class="cj-card tier1">
        <div class="cj-card-head">
          <span class="cj-icon">${a.icon}</span>
          <span class="cj-name">${a.name}</span>
          <span class="cj-tier-badge tier1">Tier-1</span>
        </div>
        <div class="cj-card-body">
          <div class="cj-role">${a.role}</div>
          <div class="cj-ip">${a.ip} · ${a.segment}</div>
          <div>
            <div class="cj-blast-lbl">Blast Radius</div>
            <div class="cj-blast">${a.blast}</div>
          </div>
          <div class="cj-exposure">
            ${expDot(a.exposure)}<span class="cj-exp-label">${expLabel[a.exposure]}</span>
            ${a.ttp ? `<span class="cj-exp-ttp" style="margin-left:auto;">${a.ttp}</span>` : ''}
          </div>
        </div>
      </div>`).join('')}
    </div>
    <div class="cj-section-head" style="margin-top:16px;"><span style="color:var(--yellow);">●</span> Critical Accounts</div>
    <div class="cj-account-list">
      ${crownJewels.accounts.map(a=>`
      <div class="cj-account">
        <span class="cj-account-icon">${a.icon}</span>
        <div style="flex:1;">
          <div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;">
            <span class="cj-account-name">${a.name}</span>
            <span class="chip chip-gray" style="font-size:9px;">${a.type}</span>
            <span style="font-size:10px;color:var(--muted);">${a.group}</span>
            <div class="cj-exposure" style="margin-left:auto;margin-top:0;padding-top:0;border-top:none;">
              ${expDot(a.exposure)}<span class="cj-exp-label">${expLabel[a.exposure]}</span>
              ${a.ttp ? `<span class="cj-exp-ttp" style="margin-left:6px;">${a.ttp}</span>` : ''}
            </div>
          </div>
          <div class="cj-account-desc">${a.desc}</div>
        </div>
      </div>`).join('')}
    </div>`;
}

// ── Open / close / tab switch ──
function openEnvContext(tab) {
  renderEcOverview();
  renderEcSegments();
  renderEcAssets();
  renderEcAccounts();
  renderEcTopology();
  renderCrownJewels();
  switchEcTab(tab || 'overview');
  document.getElementById('ec-overlay').classList.add('open');

  // Feed entry
  const agentFeed = document.getElementById('agent-feed');
  if (agentFeed) {
    const el = document.createElement('div');
    el.className = 'feed-entry fe-env';
    el.innerHTML = `<span class="fe-prefix">🏗️</span>
      <div class="fe-body"><b>EnvCtx</b> → <code style="font-size:10px;color:var(--indigo);">get_topology()</code> — ${envData.segments.length} segments · ${envData.assets.length} key assets · ${envData.accounts.length} accounts loaded</div>`;
    agentFeed.appendChild(el);
    agentFeed.scrollTop = agentFeed.scrollHeight;
  }
}

function closeEnvContext() {
  document.getElementById('ec-overlay').classList.remove('open');
}

function switchEcTab(tab) {
  document.querySelectorAll('.ec-tab').forEach(t => t.classList.toggle('on', t.dataset.ecTab === tab));
  document.querySelectorAll('.ec-pane').forEach(p => p.classList.toggle('on', p.id === `ec-pane-${tab}`));
}

function filterEcSegments(v) { renderEcSegments(v); }
function filterEcAssets(v)   { renderEcAssets(v); }
function filterEcAccounts(v) { renderEcAccounts(v); }

// ════════════════════════════════════════
// TECHNIQUE RUNBOOK  (MCP tool)
// ════════════════════════════════════════
// runbookData — see kb/runbooks.js

// Fallback entry for TTPs not in the runbook
function runbookFallback(ttpId) {
  const info = ttpInfo[ttpId] || {};
  return {
    name: info.name || ttpId,
    tactic: info.tactic || 'Unknown',
    summary: 'No detailed runbook entry exists for this technique yet. Check MITRE ATT&CK for reference.',
    evidence: [{ sev:'info', icon:'🔵', label:'Tip', text:'Contribute a runbook entry via the MCP server admin panel or your internal wiki.' }],
    queries: [],
    huntNotes: [],
    fps: [],
  };
}

/* ── Tradecraft Skills Repository ── */
// skillsData — see kb/skills.js

let activeSkillCat = 'all';

// skillDrafts — see kb/skills.js
let activeSkillTab = 'browse';

function switchSkillTab(tab) {
  activeSkillTab = tab;
  document.getElementById('sk-browse-pane').style.display = tab === 'browse' ? '' : 'none';
  document.getElementById('sk-author-pane').style.display  = tab === 'author'  ? '' : 'none';
  document.getElementById('sk-tab-browse').classList.toggle('sk-tab-on', tab === 'browse');
  document.getElementById('sk-tab-author').classList.toggle('sk-tab-on', tab === 'author');
  if (tab === 'author') renderSkillDrafts();
}

function renderSkillDrafts() {
  const el = document.getElementById('sk-draft-list');
  const countEl = document.getElementById('sk-draft-count');
  if (!el) return;
  if (countEl) countEl.textContent = skillDrafts.length + ' pending';
  if (!skillDrafts.length) {
    el.innerHTML = '<div style="font-size:11px;color:var(--muted);text-align:center;padding:20px 0;">No drafts pending review.</div>';
    return;
  }
  const catLabels = { 'credential-access':'Credential Access', 'lateral-movement':'Lateral Movement',
    'c2':'C2', 'execution':'Execution', 'persistence':'Persistence', 'defense-evasion':'Defense Evasion' };
  el.innerHTML = skillDrafts.map((dr, i) => `
    <div class="sk-draft-item">
      <div style="flex:1;min-width:0;">
        <div style="font-size:12px;font-weight:600;color:var(--text);margin-bottom:2px;">${dr.name}</div>
        <div style="font-size:10px;color:var(--muted);">${catLabels[dr.cat] || dr.cat} · by ${dr.author} · ${dr.ts}</div>
      </div>
      <span class="chip chip-yellow" style="font-size:9px;flex-shrink:0;">Pending</span>
    </div>`).join('');
}

function clearSkillDraft() {
  ['sk-draft-name','sk-draft-summary','sk-draft-patterns','sk-draft-spl','sk-draft-exclusions','sk-draft-ttps']
    .forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
  const cat = document.getElementById('sk-draft-cat'); if(cat) cat.value = '';
}

function submitSkillDraft() {
  const name = (document.getElementById('sk-draft-name')?.value || '').trim();
  const cat  = document.getElementById('sk-draft-cat')?.value || '';
  if (!name || !cat) {
    alert('Please fill in at least the Skill Name and Category before submitting.');
    return;
  }
  const now = new Date();
  const ts = now.toLocaleDateString('en-GB',{year:'numeric',month:'2-digit',day:'2-digit'}).split('/').reverse().join('-')
    + ' ' + now.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  skillDrafts.push({ id:'SK-' + (7 + skillDrafts.length) + '-draft', name, cat, author: currentUser || 'analyst', ts, status:'pending' });
  clearSkillDraft();
  renderSkillDrafts();
  // Brief success flash
  const btn = document.querySelector('#sk-author-pane .btn-primary');
  if (btn) { const orig = btn.textContent; btn.textContent = '✓ Submitted!'; btn.style.background='var(--green)'; setTimeout(()=>{ btn.textContent=orig; btn.style.background=''; }, 2000); }
}

// ─────────────────────────────────────────────
//  KNOWLEDGE BASE TAB
// ─────────────────────────────────────────────
let activeKbTab         = 'tradecraft';
let activeTradecraftTab = 'tactic';
let activeKbSkCat       = 'all';
let activeKbRbTactic    = 'all';
let kbEnvEditMode  = false;
let kbEnvSnapshot  = null; // store original values for cancel

// ── Markdown source cache & load flag ──
let _kbMdLoaded    = false;
let _activeKbMdTab = 'skills';
const _kbMdCache   = { skills: null, runbooks: null };

// ── Markdown parsers ──────────────────────────────────────────────────────

function _extractMdSections(lines) {
  const map = {};
  let cur = null;
  for (const ln of lines) {
    if (ln.startsWith('### ')) { cur = ln.slice(4).trim(); map[cur] = []; }
    else if (cur !== null)     { map[cur].push(ln); }
  }
  return map;
}

function _extractCodeBlock(lines) {
  let inside = false;
  const out = [];
  for (const ln of lines) {
    if (ln.startsWith('```')) { if (inside) break; inside = true; continue; }
    if (inside) out.push(ln);
  }
  return out.join('\n');
}

function _parseMdSkills(text) {
  const skills = [];
  // Normalise Windows (CRLF) and old Mac (CR) line endings to LF
  const norm = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  for (const sec of norm.split(/\n---\n/)) {
    const lines = sec.trim().split('\n');
    const headLine = lines.find(l => /^## SK-\d+/.test(l));
    if (!headLine) continue;
    const hm = headLine.match(/^## (SK-\d+)\s*[—–-]+\s*(.+)/);
    if (!hm) continue;
    const id   = hm[1];
    const name = hm[2].trim();

    // Parse > key: val | key: val metadata lines
    const meta = {};
    for (const ln of lines) {
      if (!ln.startsWith('> ')) continue;
      for (const part of ln.slice(2).split(' | ')) {
        const i = part.indexOf(':');
        if (i < 0) continue;
        meta[part.slice(0, i).trim()] = part.slice(i + 1).trim();
      }
    }

    // Summary: non-empty lines between heading and first ###, excluding > meta
    const summaryLines = [];
    let pastHead = false;
    for (const ln of lines) {
      if (ln.startsWith('## ')) { pastHead = true; continue; }
      if (!pastHead || ln.startsWith('> ')) continue;
      if (ln.startsWith('### ')) break;
      if (ln.trim()) summaryLines.push(ln.trim());
    }

    const smap = _extractMdSections(lines);
    const patterns    = (smap['Patterns']     || []).filter(l => l.startsWith('- ')).map(l => l.slice(2));
    const exclusions  = (smap['Exclusions']   || []).filter(l => l.startsWith('- ')).map(l => l.slice(2));
    const attackPaths = (smap['Attack Paths'] || []).filter(l => l.startsWith('- ')).map(l => {
      const p = l.slice(2).split(' | ');
      return { ttp: p[0]?.trim()||'', name: p[1]?.trim()||'', likelihood: p[2]?.trim()||'medium', desc: p.slice(3).join(' | ').trim() };
    });
    const ttps   = meta['ttps']   ? meta['ttps'].split(',').map(t => t.trim())   : [];
    const agents = meta['agents'] ? meta['agents'].split(',').map(a => a.trim()) : [];

    skills.push({
      id, name,
      skillType:  meta['type']           || 'tactic',
      cat:        meta['category']       || '',
      catLabel:   meta['category-label'] || '',
      author:     meta['author']         || '',
      version:    meta['version']        || '',
      updated:    meta['updated']        || '',
      ttps, summary: summaryLines.join(' '),
      patterns, spl: _extractCodeBlock(smap['SPL'] || []),
      exclusions, agents, attackPaths,
    });
  }
  return skills;
}

function _parseMdRunbooks(text) {
  const result = {};
  // Normalise Windows (CRLF) and old Mac (CR) line endings to LF
  const norm = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  for (const sec of norm.split(/\n---\n/)) {
    const lines = sec.trim().split('\n');
    const headLine = lines.find(l => /^## T\d{4}/.test(l));
    if (!headLine) continue;
    const hm = headLine.match(/^## (T\d{4}(?:\.\d{3})?)\s*[—–-]+\s*(.+)/);
    if (!hm) continue;
    const ttpId = hm[1];
    const name  = hm[2].trim();

    const meta = {};
    for (const ln of lines) {
      if (!ln.startsWith('> ')) continue;
      for (const part of ln.slice(2).split(' | ')) {
        const i = part.indexOf(':');
        if (i < 0) continue;
        meta[part.slice(0, i).trim()] = part.slice(i + 1).trim();
      }
    }

    const summaryLines = [];
    let pastHead = false;
    for (const ln of lines) {
      if (ln.startsWith('## ')) { pastHead = true; continue; }
      if (!pastHead || ln.startsWith('> ')) continue;
      if (ln.startsWith('### ')) break;
      if (ln.trim()) summaryLines.push(ln.trim());
    }

    const smap = _extractMdSections(lines);

    // Evidence: "- sev | text" — backtick inline code → <code>
    const evidence = (smap['Evidence'] || []).filter(l => l.startsWith('- ')).map(l => {
      const rest    = l.slice(2);
      const pipeIdx = rest.indexOf(' | ');
      const sev     = pipeIdx >= 0 ? rest.slice(0, pipeIdx).trim() : 'info';
      let   txt     = pipeIdx >= 0 ? rest.slice(pipeIdx + 3) : rest;
      txt = txt.replace(/`([^`]+)`/g, '<code>$1</code>');
      return { sev, text: txt };
    });

    // Queries: #### Label\n```spl\n...\n```
    const queries = [];
    const qLines = smap['Queries'] || [];
    let curLabel = null, inCode = false, codeLines = [];
    for (const ln of qLines) {
      if (ln.startsWith('#### ')) {
        if (curLabel !== null && codeLines.length) queries.push({ label: curLabel, spl: codeLines.join('\n') });
        curLabel = ln.slice(5).trim(); inCode = false; codeLines = [];
      } else if (ln.startsWith('```')) {
        inCode = !inCode;
      } else if (inCode) {
        codeLines.push(ln);
      }
    }
    if (curLabel !== null && codeLines.length) queries.push({ label: curLabel, spl: codeLines.join('\n') });

    // Hunt Notes: "- hunt | date | analyst | text..."
    const huntNotes = (smap['Hunt Notes'] || []).filter(l => l.startsWith('- ')).map(l => {
      const p = l.slice(2).split(' | ');
      return { hunt: p[0]?.trim()||'', date: p[1]?.trim()||'', analyst: p[2]?.trim()||'', text: p.slice(3).join(' | ').trim() };
    });

    const fps = (smap['False Positives'] || []).filter(l => l.startsWith('- ')).map(l => l.slice(2));

    result[ttpId] = { name, tactic: meta['tactic'] || '', summary: summaryLines.join(' '), evidence, queries, huntNotes, fps };
  }
  return result;
}

// ── KB init (async — fetches .md files once) ─────────────────────────────

async function initKbTab() {
  // Seed the per-tab description for the default active tab
  const desc = document.getElementById('kb-tc-desc');
  if (desc) desc.innerHTML = _tcDesc[activeTradecraftTab] || '';

  // Render immediately using inline JS data (always available, works on file://)
  renderKbSkillList(activeKbSkCat);
  renderKbDraftList();
  renderKbRunbooks();
  renderKbEnvPane();
  renderKbIocPane();

  // Fetch .md files in the background as an optional enhancement.
  // If successful, parsed data overrides the inline JS objects and re-renders.
  // If fetch fails (file:// protocol, CORS, etc.) the inline data is used as-is.
  if (!_kbMdLoaded) {
    _kbMdLoaded = true; // prevent re-entrancy
    try {
      const [sr, rr] = await Promise.all([fetch('kb/skills.md'), fetch('kb/runbooks.md')]);
      if (!sr.ok || !rr.ok) throw new Error('fetch response not ok');
      _kbMdCache.skills   = await sr.text();
      _kbMdCache.runbooks = await rr.text();

      // Populate globals (const arrays/objects can be mutated in-place)
      const parsedSkills = _parseMdSkills(_kbMdCache.skills);
      skillsData.splice(0, skillsData.length, ...parsedSkills);

      const parsedRunbooks = _parseMdRunbooks(_kbMdCache.runbooks);
      Object.keys(runbookData).forEach(k => delete runbookData[k]);
      Object.assign(runbookData, parsedRunbooks);

      // Re-render with freshly parsed markdown data
      renderKbSkillList(activeKbSkCat);
      renderKbDraftList();
      renderKbRunbooks();
    } catch(e) {
      // fetch unavailable or failed — keep using inline JS data (already rendered)
      console.info('KB markdown fetch skipped (using inline data):', e.message);
    }
  }
}

// ── KB sub-tab switch ──
function switchKbTab(tab) {
  activeKbTab = tab;
  ['tradecraft','env','ioc'].forEach(k => {
    const stab = document.getElementById('kb-stab-' + k);
    const pane = document.getElementById('kb-pane-' + k);
    if (stab) stab.classList.toggle('on', k === tab);
    if (pane) pane.classList.toggle('on', k === tab);
  });
  if (tab === 'tradecraft') { renderKbSkillList(activeKbSkCat); renderKbRunbooks(); }
  if (tab === 'env') renderKbEnvPane();
  if (tab === 'ioc') renderKbIocPane();
}

// ── Tradecraft inner tab switch ──
const _tcDesc = {
  tactic:   '<span class="ib-icon">🎯</span><span><b>Tactic Skills</b> are generic ATT&CK technique patterns that apply across any organisation. They encode hunter intuition as SPL templates, detection logic, and FP exclusion lists — use these as a starting point when hunting a technique you haven\'t seen in this environment before.</span>',
  domain:   '<span class="ib-icon">🏢</span><span><b>Domain Skills</b> are tuned to <em>this</em> environment. They encode your team\'s knowledge of this network\'s topology, tooling, service accounts, and known-good baselines — the exclusions, thresholds, and naming conventions that cut false positives in your specific org.</span>',
  runbooks: '<span class="ib-icon">📖</span><span><b>TTP Runbooks</b> are technique-level hunt guides, one per ATT&CK technique. Each covers adversary evidence indicators, hunting SPL, prior hunt notes from this environment, and known false positives. The Hypothesis Agent pulls these via <code style="font-size:10px;">get_runbook(ttp_id)</code> when generating hypotheses.</span>',
  author:   '<span class="ib-icon">✏️</span><span>Propose a new skill or an edit to an existing one. Fill in the form on the left — include behavioural patterns, an SPL template, and known FP exclusions. Submissions go into the draft queue for senior hunter review before being merged into the live knowledge base.</span>',
};

function switchTradecraftTab(tab) {
  activeTradecraftTab = tab;
  ['tactic','domain','runbooks','author'].forEach(k => {
    const stab = document.getElementById('kb-tc-stab-' + k);
    if (stab) stab.classList.toggle('on', k === tab);
  });
  const isSkills = tab === 'tactic' || tab === 'domain';
  const catBar  = document.getElementById('kb-tc-cat-bar');
  const skillsP = document.getElementById('kb-tc-pane-skills');
  const rbP     = document.getElementById('kb-tc-pane-runbooks');
  const authP   = document.getElementById('kb-tc-pane-author');
  const desc    = document.getElementById('kb-tc-desc');
  if (catBar)  catBar.style.display  = isSkills          ? '' : 'none';
  if (skillsP) skillsP.style.display = isSkills          ? '' : 'none';
  if (rbP)     rbP.style.display     = tab === 'runbooks' ? '' : 'none';
  if (authP)   authP.style.display   = tab === 'author'   ? '' : 'none';
  if (desc)    desc.innerHTML        = _tcDesc[tab] || '';
  if (isSkills)           renderKbSkillList(activeKbSkCat);
  if (tab === 'runbooks') renderKbRunbooks();
  if (tab === 'author')   renderKbDraftList();
}

// ── KB Markdown Source Viewer ─────────────────────────────────────────────

// Generate skills.md text from the live skillsData array (fallback when fetch unavailable)
function _genSkillsMd() {
  const lines = [
    '# Tradecraft Skills Repository',
    '',
    'Analyst-authored hunting skills. Each skill is a reusable detection pattern with SPL, exclusions, and downstream attack-path context.',
    '',
    '`skillType` values:',
    '- `tactic` — Generic MITRE ATT&CK technique knowledge, applies cross-org',
    '- `domain` — Environment/org-specific: tuned to THIS network\'s topology, tooling, naming conventions, and known-good baselines',
    '',
    'To add a new skill, copy any section below, paste it before the last `---`, and fill in the fields.',
    '',
  ];
  skillsData.forEach(sk => {
    lines.push('---', '');
    lines.push(`## ${sk.id} — ${sk.name}`, '');
    const ttps = Array.isArray(sk.ttps) ? sk.ttps.join(', ') : sk.ttps;
    const agents = Array.isArray(sk.agents) ? sk.agents.join(', ') : (sk.agents || '');
    lines.push(`> type: ${sk.skillType} | category: ${sk.cat} | category-label: ${sk.catLabel} | ttps: ${ttps}`);
    lines.push(`> author: ${sk.author} | version: ${sk.version} | updated: ${sk.updated} | agents: ${agents}`, '');
    lines.push(sk.summary || '', '');
    if (sk.patterns && sk.patterns.length) {
      lines.push('### Patterns');
      sk.patterns.forEach(p => lines.push('- ' + p));
      lines.push('');
    }
    if (sk.spl) {
      lines.push('### SPL');
      lines.push('```spl');
      lines.push(sk.spl);
      lines.push('```', '');
    }
    if (sk.exclusions && sk.exclusions.length) {
      lines.push('### Exclusions');
      sk.exclusions.forEach(e => lines.push('- ' + e));
      lines.push('');
    }
    if (sk.attackPaths && sk.attackPaths.length) {
      lines.push('### Attack Paths');
      sk.attackPaths.forEach(a => lines.push(`- ${a.ttp} | ${a.name} | ${a.likelihood} | ${a.desc}`));
      lines.push('');
    }
  });
  lines.push('---');
  return lines.join('\n');
}

// Generate runbooks.md text from the live runbookData object (fallback when fetch unavailable)
function _genRunbooksMd() {
  const sevLabel = { crit:'crit', high:'high', info:'info' };
  const lines = [
    '# TTP Runbooks',
    '',
    'Per-technique hunt guides — one entry per MITRE ATT&CK technique.',
    '',
    'Evidence severity levels: `crit` · `high` · `info`',
    '',
  ];
  Object.entries(runbookData).forEach(([id, rb]) => {
    lines.push('---', '');
    lines.push(`## ${id} — ${rb.name}`, '');
    lines.push(`> tactic: ${rb.tactic}`, '');
    lines.push(rb.summary || '', '');
    if (rb.evidence && rb.evidence.length) {
      lines.push('### Evidence');
      rb.evidence.forEach(ev => {
        // Strip HTML tags for display in raw markdown
        const txt = ev.text.replace(/<code>(.*?)<\/code>/g, '`$1`').replace(/<[^>]+>/g, '');
        lines.push(`- ${ev.sev} | ${txt}`);
      });
      lines.push('');
    }
    if (rb.queries && rb.queries.length) {
      lines.push('### Queries', '');
      rb.queries.forEach(q => {
        lines.push(`#### ${q.label}`);
        lines.push('```spl');
        lines.push(q.spl);
        lines.push('```', '');
      });
    }
    if (rb.huntNotes && rb.huntNotes.length) {
      lines.push('### Hunt Notes');
      rb.huntNotes.forEach(n => lines.push(`- ${n.hunt} | ${n.date} | ${n.analyst} | ${n.text}`));
      lines.push('');
    }
    if (rb.fps && rb.fps.length) {
      lines.push('### False Positives');
      rb.fps.forEach(f => lines.push('- ' + f));
      lines.push('');
    }
  });
  lines.push('---');
  return lines.join('\n');
}

// Show the markdown modal with arbitrary filename + content (single-item mode, no tabs)
function _showMdModal(filename, content) {
  const modal = document.querySelector('.kb-md-modal');
  const pre   = document.getElementById('kb-md-content');
  const name  = document.getElementById('kb-md-filename');
  if (modal) modal.classList.add('kb-md-single');
  if (name)  name.textContent = filename;
  if (pre)   pre.textContent  = content;
  document.getElementById('kb-md-overlay').classList.add('open');
}

// Generate markdown for a single skill (uses cached .md section if available)
function _genOneSkillMd(sk) {
  if (_kbMdCache.skills) {
    const norm = _kbMdCache.skills.replace(/\r\n/g,'\n').replace(/\r/g,'\n');
    const parts = norm.split(/\n---\n/);
    const section = parts.find(p => { const m = p.match(/^## (SK-\d+)/m); return m && m[1] === sk.id; });
    if (section) return section.trim();
  }
  const ttps   = Array.isArray(sk.ttps)   ? sk.ttps.join(', ')   : sk.ttps;
  const agents = Array.isArray(sk.agents) ? sk.agents.join(', ') : (sk.agents || '');
  const lines  = [
    `## ${sk.id} — ${sk.name}`, '',
    `> type: ${sk.skillType} | category: ${sk.cat} | category-label: ${sk.catLabel} | ttps: ${ttps}`,
    `> author: ${sk.author} | version: ${sk.version} | updated: ${sk.updated} | agents: ${agents}`, '',
    sk.summary || '', '',
  ];
  if (sk.patterns?.length) { lines.push('### Patterns'); sk.patterns.forEach(p => lines.push('- '+p)); lines.push(''); }
  if (sk.spl)               { lines.push('### SPL','```spl',sk.spl,'```',''); }
  if (sk.exclusions?.length){ lines.push('### Exclusions'); sk.exclusions.forEach(e => lines.push('- '+e)); lines.push(''); }
  if (sk.attackPaths?.length){ lines.push('### Attack Paths'); sk.attackPaths.forEach(a => lines.push(`- ${a.ttp} | ${a.name} | ${a.likelihood} | ${a.desc}`)); lines.push(''); }
  return lines.join('\n');
}

// Open view-source modal for a single skill card
function openSkillSource(id, evt) {
  if (evt) evt.stopPropagation();
  const sk = skillsData.find(s => s.id === id);
  if (!sk) return;
  _showMdModal(`kb/skills.md  ·  ${id}`, _genOneSkillMd(sk));
}

// Generate markdown for a single runbook (uses cached .md section if available)
function _genOneRunbookMd(ttpId, rb) {
  if (_kbMdCache.runbooks) {
    const norm = _kbMdCache.runbooks.replace(/\r\n/g,'\n').replace(/\r/g,'\n');
    const parts = norm.split(/\n---\n/);
    const section = parts.find(p => { const m = p.match(/^## (T\d{4}(?:\.\d{3})?)/m); return m && m[1] === ttpId; });
    if (section) return section.trim();
  }
  const lines = [
    `## ${ttpId} — ${rb.name}`, '',
    `> tactic: ${rb.tactic}`, '',
    rb.summary || '', '',
  ];
  if (rb.evidence?.length) {
    lines.push('### Evidence');
    rb.evidence.forEach(ev => {
      const txt = ev.text.replace(/<code>(.*?)<\/code>/g,'`$1`').replace(/<[^>]+>/g,'');
      lines.push(`- ${ev.sev} | ${txt}`);
    });
    lines.push('');
  }
  if (rb.queries?.length) {
    lines.push('### Queries','');
    rb.queries.forEach(q => { lines.push(`#### ${q.label}`,'```spl',q.spl,'```',''); });
  }
  if (rb.huntNotes?.length) {
    lines.push('### Hunt Notes');
    rb.huntNotes.forEach(n => lines.push(`- ${n.hunt} | ${n.date} | ${n.analyst} | ${n.text}`));
    lines.push('');
  }
  if (rb.fps?.length) {
    lines.push('### False Positives');
    rb.fps.forEach(f => lines.push('- '+f));
    lines.push('');
  }
  return lines.join('\n');
}

// Open view-source modal for a single runbook card
function openRunbookSource(ttpId, evt) {
  if (evt) evt.stopPropagation();
  const rb = runbookData[ttpId];
  if (!rb) return;
  _showMdModal(`kb/runbooks.md  ·  ${ttpId}`, _genOneRunbookMd(ttpId, rb));
}

function openKbMarkdown() {
  // Full-file view — show both tabs, clear single-item mode
  const modal = document.querySelector('.kb-md-modal');
  if (modal) modal.classList.remove('kb-md-single');
  const which = (activeTradecraftTab === 'runbooks') ? 'runbooks' : 'skills';
  _setKbMdTab(which);
  document.getElementById('kb-md-overlay').classList.add('open');
}

function closeKbMarkdown() {
  document.getElementById('kb-md-overlay').classList.remove('open');
  const modal = document.querySelector('.kb-md-modal');
  if (modal) modal.classList.remove('kb-md-single');
}

function switchKbMdTab(which) {
  _setKbMdTab(which);
}

function _setKbMdTab(which) {
  _activeKbMdTab = which;
  ['skills','runbooks'].forEach(k => {
    const t = document.getElementById('kb-md-tab-' + k);
    if (t) t.classList.toggle('on', k === which);
  });
  const pre  = document.getElementById('kb-md-content');
  const name = document.getElementById('kb-md-filename');
  const fname = which === 'runbooks' ? 'kb/runbooks.md' : 'kb/skills.md';
  if (name) name.textContent = fname;
  // Use fetched .md content if available, otherwise generate from inline JS data
  const content = _kbMdCache[which] ||
    (which === 'skills' ? _genSkillsMd() : _genRunbooksMd());
  if (pre) pre.textContent = content;
}

// ── KB Skills — filter ──
function filterKbSkills(cat, el) {
  activeKbSkCat = cat;
  document.querySelectorAll('[data-kbcat]').forEach(p => p.classList.toggle('sk-cat-on', p.dataset.kbcat === cat));
  renderKbSkillList(cat);
}

function renderKbSkillList(cat) {
  const el = document.getElementById('kb-sk-list');
  if (!el || typeof skillsData === 'undefined') return;
  let filtered = cat === 'all' ? skillsData : skillsData.filter(s => s.cat === cat);
  // Filter to the active inner tab type (tactic or domain)
  const type = activeTradecraftTab === 'domain' ? 'domain' : 'tactic';
  filtered = filtered.filter(s => s.skillType === type);
  if (!filtered.length) {
    el.innerHTML = '<div style="text-align:center;padding:30px 0;font-size:12px;color:var(--muted);">No skills match this filter.</div>';
    return;
  }
  el.innerHTML = filtered.map(s => renderSkillCard(s)).join('');
}


// ── TTP Runbooks ──
function filterKbRunbooks(tactic, el) {
  activeKbRbTactic = tactic;
  document.querySelectorAll('[data-rbtactic]').forEach(p => p.classList.toggle('sk-cat-on', p.dataset.rbtactic === tactic));
  renderKbRunbooks();
}

function renderKbRunbooks() {
  const el = document.getElementById('kb-rb-list');
  if (!el || typeof runbookData === 'undefined') return;
  const sevColor = { crit:'var(--red)', high:'var(--yellow)', info:'var(--blue)' };
  let entries = Object.entries(runbookData);
  if (activeKbRbTactic !== 'all') {
    entries = entries.filter(([, r]) => r.tactic && r.tactic.includes(activeKbRbTactic));
  }
  if (!entries.length) {
    el.innerHTML = '<div style="text-align:center;padding:30px 0;font-size:12px;color:var(--muted);">No runbooks match this tactic filter.</div>';
    return;
  }
  el.innerHTML = entries.map(([ttpId, r]) => {
    const evHTML = (r.evidence||[]).map(e =>
      `<div class="rb-kb-ev">
        <div class="rb-kb-ev-dot" style="background:${sevColor[e.sev]||'var(--sub)'}"></div>
        <div>${e.text.replace(/<code>/g,'<code style="font-size:10px;background:rgba(0,0,0,.3);padding:0 3px;border-radius:2px;color:#93c5fd;">').replace(/<\/code>/g,'</code>')}</div>
      </div>`
    ).join('');
    const qHTML = (r.queries||[]).map(q =>
      `<div class="rb-kb-query">
        <div class="rb-kb-qlabel">${q.label}</div>
        <div class="rb-kb-qspl">${q.spl.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>
      </div>`
    ).join('');
    const noteHTML = (r.huntNotes||[]).map(n =>
      `<div class="rb-kb-hunt-note">
        <b>${n.hunt}</b> · ${n.analyst} · ${n.date}<br>
        <span style="margin-top:4px;display:block;">${n.text}</span>
      </div>`
    ).join('');
    const fpHTML = (r.fps||[]).map(f => `<div class="rb-kb-fp-item">${f}</div>`).join('');
    return `<div class="rb-kb-card" id="rbkb-${ttpId}">
      <div class="rb-kb-head" onclick="this.closest('.rb-kb-card').classList.toggle('open')">
        <span class="rb-kb-ttp-id">${ttpId}</span>
        <span class="rb-kb-name">${r.name}</span>
        <span class="rb-kb-tactic">${r.tactic||''}</span>
        <span class="chip chip-indigo" style="font-size:9px;flex-shrink:0;">${(r.queries||[]).length} quer${(r.queries||[]).length===1?'y':'ies'}</span>
        <button class="kb-vs-btn" onclick="openRunbookSource('${ttpId}',event)" title="View raw Markdown for this runbook">📄 .md</button>
        <span class="rb-kb-chev">▾</span>
      </div>
      <div class="rb-kb-body">
        <p class="rb-kb-summary">${r.summary||''}</p>
        ${evHTML ? `<div class="rb-kb-section">Evidence Indicators</div>${evHTML}` : ''}
        ${qHTML  ? `<div class="rb-kb-section" style="margin-top:14px;">Hunting Queries</div>${qHTML}` : ''}
        ${noteHTML ? `<div class="rb-kb-section" style="margin-top:14px;">Prior Hunt Notes — This Environment</div>${noteHTML}` : ''}
        ${fpHTML  ? `<div class="rb-kb-section" style="margin-top:14px;">Known False Positives</div>${fpHTML}` : ''}
      </div>
    </div>`;
  }).join('');
}

// ── KB Draft queue ──
function renderKbDraftList() {
  const el = document.getElementById('kb-draft-list');
  const ct = document.getElementById('kb-draft-count');
  if (!el) return;
  if (ct) ct.textContent = skillDrafts.length + ' pending';
  const catLabels = { 'credential-access':'Credential Access', 'lateral-movement':'Lateral Movement',
    'c2':'C2', 'execution':'Execution', 'persistence':'Persistence', 'defense-evasion':'Defense Evasion' };
  el.innerHTML = !skillDrafts.length
    ? '<div style="font-size:11px;color:var(--muted);text-align:center;padding:20px 0;">No drafts pending review.</div>'
    : skillDrafts.map(dr => `
        <div class="sk-draft-item">
          <div style="flex:1;min-width:0;">
            <div style="font-size:12px;font-weight:600;color:var(--text);margin-bottom:2px;">${dr.name}</div>
            <div style="font-size:10px;color:var(--muted);">${catLabels[dr.cat]||dr.cat} · by ${dr.author} · ${dr.ts}</div>
          </div>
          <span class="chip chip-yellow" style="font-size:9px;flex-shrink:0;">Pending</span>
        </div>`).join('');
}

function clearKbDraft() {
  ['kb-draft-name','kb-draft-summary','kb-draft-patterns','kb-draft-spl','kb-draft-exclusions','kb-draft-ttps']
    .forEach(id => { const e = document.getElementById(id); if(e) e.value = ''; });
  const c = document.getElementById('kb-draft-cat'); if(c) c.value = '';
}

function submitKbDraft() {
  const name = (document.getElementById('kb-draft-name')?.value||'').trim();
  const cat  = document.getElementById('kb-draft-cat')?.value||'';
  if (!name || !cat) { alert('Please fill in at least Skill Name and Category.'); return; }
  const now = new Date();
  const ts = now.toISOString().slice(0,10) + ' ' + now.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  skillDrafts.push({ id:'SK-' + (8+skillDrafts.length) + '-draft', name, cat, author:currentUser||'analyst', ts, status:'pending' });
  clearKbDraft();
  renderKbDraftList();
  renderSkillDrafts(); // also update the modal's draft list
  const btn = document.getElementById('kb-submit-btn');
  if (btn) { const o=btn.textContent; btn.textContent='✓ Submitted!'; btn.style.background='var(--green)';
    setTimeout(()=>{ btn.textContent=o; btn.style.background=''; },2000); }
}

// ── KB Environment pane ──
function renderKbEnvPane() {
  const d = envData;
  if (!d) return;

  // Overview fields
  const set = (id, val) => { const e = document.getElementById(id); if(e) e.value = val ?? ''; };
  const getStat = label => (d.stats||[]).find(s=>s.label===label)?.value || '';
  set('kb-env-domain',    d.domain?.name || 'CORP.LOCAL');
  set('kb-env-endpoints', getStat('Endpoints')  || '2,412');
  set('kb-env-servers',   getStat('Servers')    || '34');
  set('kb-env-scope',     d.domain?.sites?.join(' · ') || '10.0.0.0/8 · 8 segments');
  set('kb-env-siem',      'Splunk Enterprise Security 7.3');
  set('kb-env-edr',       'CrowdStrike Falcon 7.1');
  set('kb-env-topo',      d.topology ? d.topology.replace(/<[^>]+>/g,'') : '');

  // Segments table
  const segs = d.segments || [];
  const segCount = document.getElementById('kb-seg-count');
  if (segCount) segCount.textContent = segs.length + ' segments';
  const segBody = document.getElementById('kb-seg-body');
  if (segBody) {
    segBody.innerHTML = segs.map((s,i) => {
      const cls = kbEnvEditMode ? 'kb-cell-input' : '';
      const attr = kbEnvEditMode ? '' : ' readonly style="background:transparent;border:none;color:var(--sub);font-size:11px;font-family:inherit;width:100%;outline:none;"';
      return `<tr>
        <td><input class="${cls}" data-seg="${i}" data-field="name" value="${s.name}"${attr}></td>
        <td><input class="${cls}" data-seg="${i}" data-field="cidr" value="${s.cidr||''}"${attr}></td>
        <td><input class="${cls}" data-seg="${i}" data-field="sensitivity" value="${s.sensitivity||''}"${attr}></td>
      </tr>`;
    }).join('');
  }

  // Assets table
  const assets = d.assets || [];
  const assetCount = document.getElementById('kb-asset-count');
  if (assetCount) assetCount.textContent = assets.length + ' assets';
  const assetBody = document.getElementById('kb-asset-body');
  if (assetBody) {
    assetBody.innerHTML = assets.map((a,i) => {
      const cls = kbEnvEditMode ? 'kb-cell-input' : '';
      const attr = kbEnvEditMode ? '' : ' readonly style="background:transparent;border:none;color:var(--sub);font-size:11px;font-family:inherit;width:100%;outline:none;"';
      return `<tr>
        <td><input class="${cls}" data-asset="${i}" data-field="hostname" value="${a.hostname}"${attr}></td>
        <td><input class="${cls}" data-asset="${i}" data-field="ip"       value="${a.ip}"${attr}></td>
        <td><input class="${cls}" data-asset="${i}" data-field="role"     value="${a.role||''}"${attr}></td>
        <td><input class="${cls}" data-asset="${i}" data-field="os"       value="${a.os||''}"${attr}></td>
        <td><input class="${cls}" data-asset="${i}" data-field="segment"  value="${a.segment||''}"${attr}></td>
        <td><input class="${cls}" data-asset="${i}" data-field="owner"    value="${a.owner||''}"${attr}></td>
      </tr>`;
    }).join('');
  }

  // Accounts table
  const accounts = d.accounts || [];
  const acctCount = document.getElementById('kb-acct-count');
  if (acctCount) acctCount.textContent = accounts.length + ' accounts';
  const acctBody = document.getElementById('kb-acct-body');
  if (acctBody) {
    acctBody.innerHTML = accounts.map((a,i) => {
      const cls = kbEnvEditMode ? 'kb-cell-input' : '';
      const attr = kbEnvEditMode ? '' : ' readonly style="background:transparent;border:none;color:var(--sub);font-size:11px;font-family:inherit;width:100%;outline:none;"';
      return `<tr>
        <td><input class="${cls}" data-acct="${i}" data-field="name"   value="${a.name}"${attr}></td>
        <td><input class="${cls}" data-acct="${i}" data-field="type"   value="${a.type||''}"${attr}></td>
        <td><input class="${cls}" data-acct="${i}" data-field="status" value="${a.status||''}"${attr}></td>
        <td><input class="${cls}" data-acct="${i}" data-field="normal" value="${(a.normal||'').replace(/'/g,"&#39;")}"${attr}></td>
      </tr>`;
    }).join('');
  }
}

function toggleKbEnvEdit() {
  // snapshot current values
  kbEnvSnapshot = {
    domain:   { ...envData.domain },
    stats:    (envData.stats||[]).map(s=>({...s})),
    segments: envData.segments.map(s=>({...s})),
    assets:   envData.assets.map(a=>({...a})),
    accounts: envData.accounts.map(a=>({...a})),
    topology: envData.topology,
  };
  kbEnvEditMode = true;
  document.getElementById('kb-env-edit-btn').style.display   = 'none';
  document.getElementById('kb-env-save-btn').style.display   = '';
  document.getElementById('kb-env-cancel-btn').style.display = '';
  document.getElementById('kb-env-hint').innerHTML = '🖊 Edit mode active — all fields are now editable. Click <b>Save Changes</b> when done.';
  renderKbEnvPane();
}

function cancelKbEnvEdit() {
  if (kbEnvSnapshot) {
    envData.domain   = { ...kbEnvSnapshot.domain };
    envData.stats    = kbEnvSnapshot.stats.map(s=>({...s}));
    envData.segments = kbEnvSnapshot.segments.map(s=>({...s}));
    envData.assets   = kbEnvSnapshot.assets.map(a=>({...a}));
    envData.accounts = kbEnvSnapshot.accounts.map(a=>({...a}));
    envData.topology = kbEnvSnapshot.topology;
  }
  kbEnvEditMode = false;
  kbEnvSnapshot = null;
  document.getElementById('kb-env-edit-btn').style.display   = '';
  document.getElementById('kb-env-save-btn').style.display   = 'none';
  document.getElementById('kb-env-cancel-btn').style.display = 'none';
  document.getElementById('kb-env-hint').innerHTML = 'Click <b>Edit</b> to modify any environment field. Agents will pick up changes on the next hunt.';
  renderKbEnvPane();
}

function saveKbEnvChanges() {
  // Flush overview fields
  const g = id => document.getElementById(id)?.value || '';
  if (!envData.domain) envData.domain = {};
  envData.domain.name = g('kb-env-domain');
  const setStat = (label, val) => { const s = (envData.stats||[]).find(s=>s.label===label); if(s) s.value=val; };
  setStat('Endpoints', g('kb-env-endpoints'));
  setStat('Servers',   g('kb-env-servers'));
  // Flush segment table inputs
  document.querySelectorAll('[data-seg]').forEach(inp => {
    const i = parseInt(inp.dataset.seg), f = inp.dataset.field;
    if (envData.segments[i]) envData.segments[i][f] = inp.value;
  });
  // Flush asset table inputs
  document.querySelectorAll('[data-asset]').forEach(inp => {
    const i = parseInt(inp.dataset.asset), f = inp.dataset.field;
    if (envData.assets[i]) envData.assets[i][f] = inp.value;
  });
  // Flush account table inputs
  document.querySelectorAll('[data-acct]').forEach(inp => {
    const i = parseInt(inp.dataset.acct), f = inp.dataset.field;
    if (envData.accounts[i]) envData.accounts[i][f] = inp.value;
  });
  // Flush topology
  const topoEl = document.getElementById('kb-env-topo');
  if (topoEl) envData.topology = topoEl.value;

  kbEnvEditMode = false;
  kbEnvSnapshot = null;
  document.getElementById('kb-env-edit-btn').style.display   = '';
  document.getElementById('kb-env-save-btn').style.display   = 'none';
  document.getElementById('kb-env-cancel-btn').style.display = 'none';
  const hint = document.getElementById('kb-env-hint');
  hint.innerHTML = '✓ Changes saved — agents will use updated context on next invocation.';
  hint.style.color = 'var(--green)';
  setTimeout(() => {
    hint.innerHTML = 'Click <b>Edit</b> to modify any environment field. Agents will pick up changes on the next hunt.';
    hint.style.color = '';
  }, 3000);
  renderKbEnvPane();
}

// ── IOC Repository ──
function renderKbIocPane() {
  const tbody = document.getElementById('ioc-table-body');
  if (!tbody) return;

  // Filtered set
  let rows = iocRepository.filter(r => {
    const typeMatch   = activeIocTypeFilter   === 'all' || r.type   === activeIocTypeFilter;
    const statusMatch = activeIocStatusFilter === 'all' || r.status === activeIocStatusFilter;
    return typeMatch && statusMatch;
  });

  // Stats (always whole set)
  const all = iocRepository;
  const setText = (id, v) => { const e = document.getElementById(id); if(e) e.textContent = v; };
  setText('ioc-stat-total',  all.length);
  setText('ioc-stat-ip',     all.filter(r=>r.type==='IP'     && (r.status==='blocked'||r.status==='isolated')).length);
  setText('ioc-stat-domain', all.filter(r=>r.type==='Domain' && r.status==='blocked').length);
  setText('ioc-stat-hash',   all.filter(r=>r.type==='Hash'||r.type==='JA3').length);
  setText('ioc-stat-acct',   all.filter(r=>r.type==='Account').length);

  const sevColor  = { c:'var(--red)', h:'var(--orange)', m:'var(--yellow)', l:'var(--green)' };
  const sevLabel  = { c:'Critical',   h:'High',          m:'Medium',        l:'Low'         };
  const typeClass = { IP:'ioc-t-ip', Domain:'ioc-t-domain', Hash:'ioc-t-hash', JA3:'ioc-t-ja3', Account:'ioc-t-account' };
  const statusIco = { blocked:'🚫', monitoring:'👁️', isolated:'🔒', suspended:'⛔', cleared:'✓' };

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:30px;color:var(--muted);font-size:12px;">No IOCs match the current filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(r => {
    const u = users[r.analyst] || { initials:'?', bg:'rgba(100,116,139,.2)', color:'var(--sub)' };
    return `<tr>
      <td style="padding-left:24px;"><span class="ioc-type ${typeClass[r.type]||''}">${r.type}</span></td>
      <td><span class="ioc-val">${r.value}</span></td>
      <td><span style="font-size:10px;color:var(--blue);font-weight:600;">${r.hunt}</span></td>
      <td><span style="font-size:10px;color:var(--sub);">${r.ttp||'—'}</span></td>
      <td><span style="font-size:11px;font-weight:600;color:${sevColor[r.sev]||'var(--sub)'};">${sevLabel[r.sev]||r.sev}</span></td>
      <td><span class="ioc-status ioc-s-${r.status}">${statusIco[r.status]||''} ${r.status.charAt(0).toUpperCase()+r.status.slice(1)}</span></td>
      <td><div style="display:flex;align-items:center;gap:5px;">
        <div class="user-av" style="width:16px;height:16px;font-size:7px;background:${u.bg};color:${u.color};flex-shrink:0;">${u.initials}</div>
        <span>${r.analyst}</span>
      </div></td>
      <td style="font-size:10px;white-space:nowrap;color:var(--muted);">${r.ts}</td>
      <td style="max-width:200px;font-size:10px;color:var(--muted);line-height:1.4;">${r.note}</td>
    </tr>`;
  }).join('');
}

function filterKbIoc(dimension, value, el) {
  if (dimension === 'type') {
    activeIocTypeFilter = value;
    document.querySelectorAll('[data-ioctype]').forEach(b => b.classList.toggle('on', b.dataset.ioctype === value));
  } else {
    activeIocStatusFilter = value;
    document.querySelectorAll('[data-iocstatus]').forEach(b => b.classList.toggle('on', b.dataset.iocstatus === value));
  }
  renderKbIocPane();
}

function addKbIoc() {
  const type   = document.getElementById('ioc-add-type')?.value || 'IP';
  const value  = (document.getElementById('ioc-add-value')?.value || '').trim();
  const ttp    = (document.getElementById('ioc-add-ttp')?.value   || '').trim();
  const status = document.getElementById('ioc-add-status')?.value || 'monitoring';
  if (!value) { alert('Please enter an IOC value.'); return; }
  const now = new Date();
  const ts  = now.toISOString().slice(0,10) + ' ' + now.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  iocRepository.push({
    id: 'IOC-' + String(iocRepository.length + 1).padStart(3,'0'),
    type, value, hunt: 'TH-2026-' + activeKeepHunt,
    ttp: ttp || '—', sev: 'h', status,
    analyst: currentUser || 'analyst', ts, note: 'Manually added',
  });
  document.getElementById('ioc-add-value').value = '';
  document.getElementById('ioc-add-ttp').value   = '';
  renderKbIocPane();
}

function exportKbIoc() {
  const headers = ['ID','Type','Value','Hunt','TTP','Severity','Status','Analyst','Added','Note'];
  const rows = iocRepository.map(r =>
    [r.id,r.type,r.value,r.hunt,r.ttp,r.sev,r.status,r.analyst,r.ts,r.note].map(v=>`"${(v||'').replace(/"/g,'""')}"`).join(',')
  );
  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], { type:'text/csv' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = 'ioc-repository-' + new Date().toISOString().slice(0,10) + '.csv';
  a.click(); URL.revokeObjectURL(url);
}

function openSkillsRepo() {
  // Navigate to Knowledge Base tab
  const kbTab = Array.from(document.querySelectorAll('.nav-tab')).find(t => t.textContent.includes('Knowledge Base'));
  if (kbTab) { goTab('kb', kbTab); initKbTab(); }
  else { document.getElementById('sk-overlay').classList.add('open'); switchSkillTab('browse'); }
}
function closeSkillsRepo() {
  document.getElementById('sk-overlay').classList.remove('open');
}
function filterSkills(cat, el) {
  activeSkillCat = cat;
  document.querySelectorAll('.sk-cat-pill').forEach(p => p.classList.remove('sk-cat-on'));
  el.classList.add('sk-cat-on');
  renderSkillsRepo(cat);
}
function renderSkillsRepo(cat) {
  const list = document.getElementById('sk-list');
  if (!list) return;
  const filtered = cat === 'all' ? skillsData : skillsData.filter(s => s.cat === cat);
  list.innerHTML = filtered.map(renderSkillCard).join('');
}
function toggleSkillCard(el) { el.classList.toggle('open'); }
function toggleDetChain(el) { el.closest('.det-chain').classList.toggle('open'); }
function renderSkillCard(sk) {
  const agentColor = {orchestrator:'blue',hypothesis:'teal',dataeng:'indigo',tradecraft:'yellow',detection:'green',validation:'purple'};
  const agentIcon  = {orchestrator:'🎛️',hypothesis:'💡',dataeng:'🗄️',tradecraft:'🧠',detection:'⚙️',validation:'✅'};
  const ttpChips = sk.ttps.map(t=>`<span class="chip chip-indigo" style="font-size:9px;padding:1px 5px;">${t}</span>`).join('');
  const agentChips = sk.agents.map(a=>`<span class="chip chip-${agentColor[a]||'gray'}" style="font-size:10px;">${agentIcon[a]||''} ${a}</span>`).join('');
  const patterns = sk.patterns.map(p=>`<li>${p}</li>`).join('');
  const excl = sk.exclusions.map(e=>`<li>${e}</li>`).join('');
  return `
  <div class="sk-card sk-border-${sk.cat}" onclick="toggleSkillCard(this)">
    <div class="sk-card-head">
      <span class="sk-id">${sk.id}</span>
      <span class="sk-name">${sk.name}</span>
      <span class="sk-cat-badge sk-cat-${sk.cat}">${sk.catLabel}</span>
      <span class="chip chip-gray" style="font-size:9px;margin-left:4px;">${sk.version}</span>
      <button class="kb-vs-btn" onclick="openSkillSource('${sk.id}',event)" title="View raw Markdown for this skill">📄 .md</button>
      <span class="sk-chevron" style="margin-left:2px;">▼</span>
    </div>
    <div class="sk-card-body">
      <div class="sk-meta-row">
        <span>✍️ <strong>${sk.author}</strong></span>
        <span>Updated ${sk.updated}</span>
        <span style="display:flex;gap:3px;flex-wrap:wrap;">${ttpChips}</span>
      </div>
      <p class="sk-summary">${sk.summary}</p>
      <div class="sk-section-lbl">Behavioral Patterns</div>
      <ul class="sk-patterns">${patterns}</ul>
      <div class="sk-section-lbl">SPL Template</div>
      <pre class="sk-spl">${sk.spl}</pre>
      <div class="sk-section-lbl">FP Exclusions</div>
      <ul class="sk-excl">${excl}</ul>
      <div class="sk-section-lbl">Suggested Attack Paths</div>
      <div class="sk-path-list">
        ${sk.attackPaths.map(p=>`
        <div class="sk-path-item ${p.likelihood}">
          <div class="sk-path-top">
            <span class="sk-path-ttp">${p.ttp}</span>
            <span class="sk-path-name">${p.name}</span>
            <span class="sk-path-lhood ${p.likelihood}">${p.likelihood}</span>
          </div>
          <div class="sk-path-desc">${p.desc}</div>
        </div>`).join('')}
      </div>
      <div class="sk-ver-row">
        <span>Consumed by:</span>
        <div class="sk-agents-row">${agentChips}</div>
      </div>
    </div>
  </div>`;
}

function toggleToolTile(tile) {
  const grid = tile.parentElement;
  const tiles = Array.from(grid.querySelectorAll(':scope > .tool-tile'));
  const idx = tiles.indexOf(tile);
  const pairIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
  const pair = tiles[pairIdx];
  const willOpen = !tile.classList.contains('open');
  tile.classList.toggle('open', willOpen);
  if (pair) pair.classList.toggle('open', willOpen);
}

function openRunbook(ttpId) {
  const rb = runbookData[ttpId] || runbookFallback(ttpId);
  const modal = document.getElementById('rb-modal');
  if (!modal) return;

  document.getElementById('rb-modal-ttp-id').textContent = ttpId;
  document.getElementById('rb-modal-title-text').textContent = rb.name;
  document.getElementById('rb-tactic-chip').textContent = rb.tactic;
  document.getElementById('rb-summary').textContent = rb.summary;

  // Evidence tips
  const evEl = document.getElementById('rb-evidence');
  evEl.innerHTML = rb.evidence.length
    ? rb.evidence.map(e => `
      <div class="rb-tip rb-tip-${e.sev === 'crit' ? 'crit' : e.sev === 'high' ? 'high' : 'info'}">
        <span class="rb-tip-icon">${e.icon}</span>
        <div class="rb-tip-body">
          <div class="rb-tip-label ${e.sev === 'crit' ? 'crit' : e.sev === 'high' ? 'high' : 'info'}">${e.label}</div>
          <div class="rb-tip-text">${e.text}</div>
        </div>
      </div>`).join('')
    : '<div style="font-size:11px;color:var(--muted);">No evidence tips for this technique.</div>';

  // Detection queries
  const qEl = document.getElementById('rb-queries');
  qEl.innerHTML = rb.queries.length
    ? rb.queries.map((q, i) => `
      <div class="rb-query-label">${q.label}</div>
      <div class="rb-query" id="rb-q-${i}">${q.spl.replace(/</g,'&lt;').replace(/>/g,'&gt;')}
        <button class="rb-use-query-btn" onclick="useRunbookQuery(${i},'${ttpId}')">Use in Check ↗</button>
      </div>`).join('')
    : '<div style="font-size:11px;color:var(--muted);">No query templates for this technique.</div>';

  // Hunt notes
  const hnEl = document.getElementById('rb-hunt-notes');
  hnEl.innerHTML = rb.huntNotes.length
    ? rb.huntNotes.map(n => `
      <div class="rb-note">
        <div class="rb-note-meta">
          <span class="rb-note-hunt">${n.hunt}</span>
          <span class="rb-note-date">${n.date}</span>
          <span class="rb-note-analyst">— ${n.analyst}</span>
        </div>
        <div class="rb-note-text">${n.text.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>
      </div>`).join('')
    : '<div style="font-size:11px;color:var(--muted);">No prior hunt notes for this technique.</div>';

  // FP guidance
  const fpEl = document.getElementById('rb-fps');
  fpEl.innerHTML = rb.fps.length
    ? rb.fps.map(fp => `<div class="rb-fp">${fp.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>`).join('')
    : '<div style="font-size:11px;color:var(--muted);">No false positive guidance recorded.</div>';

  document.getElementById('rb-overlay').classList.add('open');

  // Log a feed entry to show the MCP tool was called
  const agentFeed = document.getElementById('agent-feed');
  if (agentFeed) {
    const el = document.createElement('div');
    el.className = 'feed-entry fe-runbook';
    el.innerHTML = `<span class="fe-prefix">📖</span>
      <div class="fe-body"><b>Runbook</b> → <code style="font-size:10px;color:var(--indigo);">get_runbook("${ttpId}")</code> — ${rb.name} · ${rb.evidence.length} evidence tips, ${rb.huntNotes.length} prior hunt note(s)</div>`;
    agentFeed.appendChild(el);
    agentFeed.scrollTop = agentFeed.scrollHeight;
  }
}

function closeRunbook() {
  document.getElementById('rb-overlay').classList.remove('open');
}

function useRunbookQuery(idx, ttpId) {
  const rb = runbookData[ttpId] || runbookFallback(ttpId);
  const q = rb.queries[idx];
  if (!q) return;
  const editor = document.getElementById('spl-editor') || document.querySelector('.query-editor');
  if (editor) {
    editor.value = q.spl;
    editor.focus();
    closeRunbook();
    // Navigate to Check tab
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('on'));
    const checkTab = document.querySelector('[onclick*="check"]') || document.querySelector('.nav-tab:nth-child(4)');
    if (checkTab) checkTab.click();
  }
}

// Wire up TTP chips in the UI to open the runbook on click
(function() {
  function attachRunbookTriggers() {
    document.querySelectorAll('.chip[data-ttp], .ttp-id[data-ttp], .mt[data-ttp]').forEach(el => {
      if (el.dataset.rbBound) return;
      el.dataset.rbBound = '1';
      el.style.cursor = 'pointer';
      el.title = 'Open Technique Runbook';
      el.addEventListener('click', e => {
        e.stopPropagation();
        openRunbook(el.dataset.ttp);
      });
    });
  }
  // Run once now and again after any pipeline step renders new chips
  attachRunbookTriggers();
  const obs = new MutationObserver(attachRunbookTriggers);
  obs.observe(document.body, { childList: true, subtree: true });
})();

// ════════════════════════════════════════
// RULE VALIDATION  (MCP tool)
// ════════════════════════════════════════
const rvData = {
  meta: {
    runAt: '2026-05-18T09:14:22Z',
    source: 'Detection Logic Agent',
    index: 'main, windows, sysmon, network',
    lookback: '30d',
  },
  stats: { total: 9, pass: 6, warn: 2, fail: 1 },
  rules: [
    {
      id: 'RV-001', ttp: 'T1053.005', name: 'Scheduled Task — schtasks.exe /create',
      format: 'spl', status: 'pass',
      detail: 'Schema validated. All fields resolve in current CIM Endpoint data model.',
      fpRate: 1.8, coverage: 94,
      query: `index=sysmon EventCode=1
| where process_name="schtasks.exe" AND match(process_commandline, "/create")
| where NOT match(process_commandline, "ConfigMgr_*|SCCM|MicrosoftEdge")
| stats count by host, user, process_commandline
| where count < 3`,
      warnings: [],
      backtest: { hits: 14, fps: 1, days: 30, peakDay: '2026-05-12', peakHits: 4 },
      deploy: { status: 'queued', severity: 'High', schedule: '5m', approvalRequired: false },
    },
    {
      id: 'RV-002', ttp: 'T1547.001', name: 'Registry Run Key Persistence',
      format: 'spl', status: 'warn',
      detail: 'Field registry_value_data not present in all forwarder versions — consider registry_value or Registry.registry_value_data.',
      fpRate: 3.2, coverage: 78,
      query: `index=sysmon EventCode=13
| where registry_key_path IN ("*\\\\Run\\\\*","*\\\\RunOnce\\\\*")
| where NOT match(registry_value_data, "OneDrive|Teams|CrowdStrike|Splunk")
| stats values(registry_value_data) as values by host, user, registry_key_path`,
      warnings: ['registry_value_data field absent on legacy UF 8.x agents — 22% coverage gap'],
      backtest: { hits: 7, fps: 2, days: 30, peakDay: '2026-05-09', peakHits: 3 },
      deploy: { status: 'pending-fix', severity: 'Medium', schedule: '10m', approvalRequired: false },
    },
    {
      id: 'RV-003', ttp: 'T1558.003', name: 'Kerberoasting — RC4 TGS-REQ',
      format: 'spl', status: 'pass',
      detail: 'Schema validated. BackupExec and MSSQLSvc SPN exclusions applied.',
      fpRate: 0.4, coverage: 99,
      query: `index=windows EventCode=4769
| where ticket_encryption_type=0x17
| where NOT match(service_name, "BackupExec|MSSQLSvc|krbtgt")
| bucket span=5m _time
| stats dc(service_name) as uniq_spns, count by _time, src_ip, user
| where uniq_spns > 3 OR count > 10`,
      warnings: [],
      backtest: { hits: 3, fps: 0, days: 30, peakDay: '2026-05-06', peakHits: 2 },
      deploy: { status: 'queued', severity: 'Critical', schedule: '5m', approvalRequired: true },
    },
    {
      id: 'RV-004', ttp: 'T1078.002', name: 'Valid Domain Accounts — Off-Hours Logon',
      format: 'spl', status: 'pass',
      detail: 'Schema OK. Baseline comparison using lookup table corp_logon_baseline.',
      fpRate: 2.1, coverage: 91,
      query: `index=windows EventCode=4624 Logon_Type=3
| eval hour=tonumber(strftime(_time,"%H"))
| where hour < 6 OR hour > 21
| lookup corp_logon_baseline user OUTPUT expected_hours
| where isnull(expected_hours) OR hour NOT IN (expected_hours)
| stats count, values(src_ip) as sources by user, host`,
      warnings: [],
      backtest: { hits: 22, fps: 3, days: 30, peakDay: '2026-05-14', peakHits: 9 },
      deploy: { status: 'queued', severity: 'High', schedule: '15m', approvalRequired: false },
    },
    {
      id: 'RV-005', ttp: 'T1570', name: 'Lateral Tool Transfer — SMB Drop',
      format: 'spl', status: 'pass',
      detail: 'Schema validated. File extension allow-list tightly scoped.',
      fpRate: 1.1, coverage: 88,
      query: `index=sysmon EventCode=11
| where match(target_filename, "\\\\(ADMIN|C|IPC)\\$\\\\.*\\.(exe|dll|bat|ps1|vbs)$")
| where NOT match(process_image, "\\\\msiexec\\.exe|\\\\wusa\\.exe|\\\\svchost\\.exe")
| stats values(target_filename) as files, count by host, user, process_image
| where count > 1`,
      warnings: [],
      backtest: { hits: 5, fps: 0, days: 30, peakDay: '2026-05-10', peakHits: 3 },
      deploy: { status: 'queued', severity: 'High', schedule: '5m', approvalRequired: false },
    },
    {
      id: 'RV-006', ttp: 'T1003.001', name: 'LSASS Memory Access — Suspicious Handle',
      format: 'spl', status: 'pass',
      detail: 'Schema OK. AV/EDR process exclusions applied from runbook FP list.',
      fpRate: 0.6, coverage: 96,
      query: `index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe"
| where NOT match(SourceImage, "MsMpEng|CrowdStrike|SentinelOne|AVP|bdservicehost")
| eval suspicious_access=if(match(GrantedAccess,"0x1fffff|0x1010|0x143a"),1,0)
| where suspicious_access=1
| stats count, values(SourceImage) as sources by host, user`,
      warnings: [],
      backtest: { hits: 1, fps: 0, days: 30, peakDay: '2026-05-15', peakHits: 1 },
      deploy: { status: 'queued', severity: 'Critical', schedule: '1m', approvalRequired: true },
    },
    {
      id: 'RV-007', ttp: 'T1558.001', name: 'Golden Ticket — TGT Unusual Lifetime',
      format: 'sigma', status: 'warn',
      detail: 'Sigma rule translates correctly. Splunk-translated SPL missing field: TicketOptions — requires custom extraction.',
      fpRate: 0.2, coverage: 62,
      query: `title: Golden Ticket Detection
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketOptions: '0x40810000'
    TicketEncryptionType: '0x12'
  filter:
    ServiceName: 'krbtgt'
  condition: selection and not filter
falsepositives:
  - Legitimate privileged service accounts`,
      warnings: ['TicketOptions field not extracted in current Splunk TA — add props.conf transform before deploy'],
      backtest: { hits: 0, fps: 0, days: 30, peakDay: null, peakHits: 0 },
      deploy: { status: 'pending-fix', severity: 'Critical', schedule: '1m', approvalRequired: true },
    },
    {
      id: 'RV-008', ttp: 'T1059.001', name: 'PowerShell — Encoded Command Execution',
      format: 'kql', status: 'pass',
      detail: 'KQL validated against Defender for Endpoint schema. All fields present.',
      fpRate: 4.3, coverage: 85,
      query: `DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc","-EncodedCommand","-ec ")
| where not(ProcessCommandLine has_any ("WindowsUpdate","MicrosoftEdge","ConfigMgr"))
| summarize count(), dcount(DeviceName) by InitiatingProcessFileName, ProcessCommandLine, bin(Timestamp, 5m)
| where count_ > 2`,
      warnings: [],
      backtest: { hits: 31, fps: 7, days: 30, peakDay: '2026-05-11', peakHits: 12 },
      deploy: { status: 'queued', severity: 'Medium', schedule: '5m', approvalRequired: false },
    },
    {
      id: 'RV-009', ttp: 'T1562.001', name: 'Disable Windows Defender via Registry',
      format: 'yara', status: 'fail',
      detail: 'YARA rule references private string variable $disable_key before declaration. Compilation fails.',
      fpRate: null, coverage: 0,
      query: `rule Disable_WindowsDefender_Registry {
  meta:
    description = "Detects registry modification to disable Windows Defender"
    author = "Detection Logic Agent"
    ttp = "T1562.001"
  strings:
    $reg_path = "SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender" ascii wide
    $disable_val = "DisableAntiSpyware" ascii
  condition:
    all of them
}`,
      warnings: ['YARA compilation failed: string $disable_key referenced before declaration (line 14)', 'Deploy blocked until syntax error resolved'],
      backtest: { hits: 0, fps: 0, days: 30, peakDay: null, peakHits: 0 },
      deploy: { status: 'blocked', severity: 'High', schedule: null, approvalRequired: false },
    },
  ],
};

function renderRvResults() {
  const s = rvData.stats;
  document.getElementById('rv-stats').innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px;">
      <div style="background:var(--s2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px;text-align:center;">
        <div style="font-size:22px;font-weight:700;color:var(--text);">${s.total}</div>
        <div style="font-size:10px;color:var(--muted);margin-top:2px;">Total Rules</div>
      </div>
      <div style="background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);border-radius:var(--radius-sm);padding:12px;text-align:center;">
        <div style="font-size:22px;font-weight:700;color:#4ade80;">${s.pass}</div>
        <div style="font-size:10px;color:var(--muted);margin-top:2px;">Pass</div>
      </div>
      <div style="background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.2);border-radius:var(--radius-sm);padding:12px;text-align:center;">
        <div style="font-size:22px;font-weight:700;color:#fbbf24;">${s.warn}</div>
        <div style="font-size:10px;color:var(--muted);margin-top:2px;">Warn</div>
      </div>
      <div style="background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:var(--radius-sm);padding:12px;text-align:center;">
        <div style="font-size:22px;font-weight:700;color:#f87171;">${s.fail}</div>
        <div style="font-size:10px;color:var(--muted);margin-top:2px;">Fail</div>
      </div>
    </div>`;

  const statusOrder = { fail: 0, warn: 1, pass: 2 };
  const sorted = [...rvData.rules].sort((a, b) => statusOrder[a.status] - statusOrder[b.status]);

  document.getElementById('rv-rules-list').innerHTML = sorted.map(r => `
    <div class="rv-rule">
      <div style="display:flex;align-items:flex-start;gap:10px;flex-wrap:wrap;">
        <span class="rv-status rv-${r.status}">${r.status.toUpperCase()}</span>
        <span class="rv-format rv-fmt-${r.format}">${r.format.toUpperCase()}</span>
        <div style="flex:1;min-width:160px;">
          <div style="font-weight:700;font-size:12px;">${r.name}</div>
          <div style="font-size:10px;color:var(--muted);margin-top:1px;">${r.id} · ${r.ttp}</div>
        </div>
        ${r.fpRate !== null ? `<div style="text-align:right;flex-shrink:0;">
          <div style="font-size:11px;font-weight:700;color:${r.fpRate > 3 ? '#fbbf24' : 'var(--green)'};">${r.fpRate}% FP</div>
          <div style="font-size:10px;color:var(--muted);">${r.coverage}% cov</div>
        </div>` : ''}
      </div>
      <div style="margin-top:8px;font-size:11px;color:var(--muted);">${r.detail}</div>
      ${r.warnings.map(w => `<div style="margin-top:6px;padding:5px 8px;background:rgba(234,179,8,.08);border-left:2px solid #fbbf24;border-radius:3px;font-size:10px;color:#fbbf24;">⚠ ${w}</div>`).join('')}
      <pre class="rv-query" style="margin-top:10px;">${r.query.trim()}</pre>
    </div>`).join('');
}

function renderRvBacktest() {
  document.getElementById('rv-backtest-list').innerHTML = rvData.rules.map(r => `
    <div class="rv-rule">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px;">
        <span class="rv-status rv-${r.status}">${r.status.toUpperCase()}</span>
        <div style="flex:1;">
          <div style="font-weight:700;font-size:12px;">${r.name}</div>
          <div style="font-size:10px;color:var(--muted);">${r.id} · ${r.ttp} · lookback: ${r.backtest.days}d</div>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:8px;">
        <div style="background:var(--s2);border:1px solid var(--border);border-radius:4px;padding:8px;text-align:center;">
          <div style="font-size:18px;font-weight:700;">${r.backtest.hits}</div>
          <div style="font-size:9px;color:var(--muted);">Total Hits</div>
        </div>
        <div style="background:${r.backtest.fps > 0 ? 'rgba(234,179,8,.07)' : 'var(--s2)'};border:1px solid ${r.backtest.fps > 0 ? 'rgba(234,179,8,.25)' : 'var(--border)'};border-radius:4px;padding:8px;text-align:center;">
          <div style="font-size:18px;font-weight:700;color:${r.backtest.fps > 0 ? '#fbbf24' : 'inherit'}">${r.backtest.fps}</div>
          <div style="font-size:9px;color:var(--muted);">False Positives</div>
        </div>
        <div style="background:var(--s2);border:1px solid var(--border);border-radius:4px;padding:8px;text-align:center;">
          <div style="font-size:18px;font-weight:700;">${r.backtest.peakHits}</div>
          <div style="font-size:9px;color:var(--muted);">Peak / Day</div>
        </div>
      </div>
      ${r.backtest.peakDay ? `<div style="font-size:10px;color:var(--muted);">Peak activity day: <b>${r.backtest.peakDay}</b></div>` : '<div style="font-size:10px;color:var(--muted);">No hits in lookback period</div>'}
    </div>`).join('');
}

function renderRvDeploy() {
  const statusLabel = { queued:'Queued', 'pending-fix':'Pending Fix', blocked:'Blocked', deployed:'Deployed' };
  const statusColor = { queued:'var(--blue)', 'pending-fix':'#fbbf24', blocked:'#f87171', deployed:'#4ade80' };

  document.getElementById('rv-deploy-list').innerHTML = rvData.rules.map(r => `
    <div class="rv-rule" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
      <div style="flex:1;min-width:160px;">
        <div style="font-weight:700;font-size:12px;">${r.name}</div>
        <div style="font-size:10px;color:var(--muted);margin-top:1px;">${r.id} · ${r.ttp}</div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
        ${r.deploy.schedule ? `<span style="font-size:10px;color:var(--muted);font-family:monospace;">every ${r.deploy.schedule}</span>` : ''}
        <span class="chip chip-${r.deploy.severity === 'Critical' ? 'red' : r.deploy.severity === 'High' ? 'yellow' : 'blue'}" style="font-size:10px;">${r.deploy.severity}</span>
        ${r.deploy.approvalRequired ? `<span class="chip" style="font-size:10px;background:rgba(139,92,246,.1);color:#a78bfa;border:1px solid rgba(139,92,246,.25);">Approval Required</span>` : ''}
        <span style="font-size:11px;font-weight:700;color:${statusColor[r.deploy.status]};">${statusLabel[r.deploy.status] || r.deploy.status}</span>
      </div>
    </div>`).join('');
}

function openRuleValidation() {
  renderRvResults();
  renderRvBacktest();
  renderRvDeploy();
  switchRvTab('results');
  document.getElementById('rv-overlay').classList.add('open');

  const agentFeed = document.getElementById('agent-feed');
  if (agentFeed) {
    const el = document.createElement('div');
    el.className = 'feed-entry fe-rv';
    const s = rvData.stats;
    el.innerHTML = `<span class="fe-prefix">✅</span><div class="fe-body"><b>RuleVal</b> → <code style="font-size:10px;color:var(--blue);">validate_all()</code> — ${s.total} rules · ${s.pass} pass · ${s.warn} warn · ${s.fail} fail</div>`;
    agentFeed.appendChild(el);
    agentFeed.scrollTop = agentFeed.scrollHeight;
  }
}

function closeRuleValidation() {
  document.getElementById('rv-overlay').classList.remove('open');
}

function switchRvTab(tab) {
  document.querySelectorAll('.rv-tab').forEach(t => t.classList.toggle('on', t.dataset.rvTab === tab));
  document.querySelectorAll('.rv-pane').forEach(p => p.classList.toggle('on', p.id === `rv-pane-${tab}`));
}
