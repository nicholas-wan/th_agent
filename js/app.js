/* ════════════════════════════════════════════════════════════════════════
   PrimeTH — Application Logic
   Edit this file to change behaviour. Loaded by index.html via <script src>.
   IOC + gate-decision data live in kb/iocs.js and kb/gate-decisions.js.
   Skills, runbooks, and environment are loaded at runtime from kb/*.md.
   ════════════════════════════════════════════════════════════════════════ */


/* ── KB Globals ──────────────────────────────────────────────────────────
   skillsData, skillDrafts  → kb/skills-fallback.js  (edit kb/skills.md to add skills)
   runbookData              → kb/runbooks-fallback.js (edit kb/runbooks.md to add runbooks)
   envData, crownJewels     → kb/environment-fallback.js
   All three are overwritten at runtime from kb/*.md when served via HTTP.
   ──────────────────────────────────────────────────────────────────────── */

/* ── envData + crownJewels ──────────────────────────────────────────────
   Declared in kb/environment-fallback.js (edit kb/environment.md to change).
   ──────────────────────────────────────────────────────────────────────── */
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
  // Subhunt sidebar is not relevant on the Agents tab
  const sidebar = document.getElementById('subhunt-sidebar');
  if (sidebar) sidebar.classList.toggle('sh-hidden-for-agents', name === 'agents');
}

function updateSubTabGating() {
  const locked = typeof pipelineLocked !== 'undefined' && pipelineLocked;
  const step   = typeof maxStep !== 'undefined' ? maxStep : -1;
  // Thresholds: observe=step1, check=step3, keep=step4
  const gates  = { observe: 1, check: 3, keep: 4 };
  Object.entries(gates).forEach(([tab, threshold]) => {
    const el = document.getElementById('subtab-' + tab);
    if (!el) return;
    const open = locked || step >= threshold;
    el.style.opacity       = open ? '' : '0.38';
    el.style.pointerEvents = open ? '' : 'none';
    el.title               = open ? '' : 'Complete earlier pipeline stages to unlock';
  });
}

// ── Per-hunt Check tab metadata ──
const checkHuntMeta = {
  '041': {
    cti: 'CISA AA24-038A — Volt Typhoon',
    ttpCount: '8 extracted · 4 selected',
    hypCount: '4 hypotheses under test',
    statusClass: 'chip-red', statusText: 'Volt Typhoon · Active',
    active: true,
  },
  '042': {
    cti: 'Follow-up from TH-2026-041 — DCSync Staging',
    ttpCount: '3 extracted · 3 selected',
    hypCount: '3 hypotheses under test',
    statusClass: 'chip-red', statusText: 'DCSync Staging · Active',
    active: true,
  },
  '040': {
    cti: 'FS-ISAC TLP:AMBER — FIN7 Ransomware',
    ttpCount: '9 extracted · 2 prioritized', hypCount: 'Hunt closed — 2 hypotheses confirmed',
    statusClass: 'chip-green', statusText: 'FIN7 Ransomware · Closed',
    active: false,
    closedMsg: 'This hunt closed on 2026-04-24. Detection queries and final results are archived in the <b>Keep</b> tab.',
  },
  '039': {
    cti: 'CISA Supply Chain Advisory',
    ttpCount: '7 extracted · 2 prioritized', hypCount: 'Hunt closed — 2 hypotheses confirmed',
    statusClass: 'chip-green', statusText: 'Supply Chain · Closed',
    active: false,
    closedMsg: 'This hunt closed on 2026-04-14. Detection queries and final results are archived in the <b>Keep</b> tab.',
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

  if (!cm.active) {
    const archivedSum = closedCheckSummaries[keepId];
    const archivedRAA = closedRAAResults[keepId];

    if (archivedSum) {
      // Closed hunt with archived results — show summary + RAA
      renderCheckSummary(false, archivedSum);
      renderRAAResults(archivedRAA || null);
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

  // Active hunt — load this hunt's Check data and re-render
  _activeHuntId = keepId;
  renderCheckSummary(true);
  renderRAAResults();
  renderGeneratedRulesCard();
}

// ── Hunt meta for detail pane header ──
const huntMeta = {
  'TH-2026-041': { status:'Volt Typhoon · Active', statusClass:'chip-red', title:'Volt Typhoon Lateral Movement & Credential Harvesting — Corp Domain', defaultTab:'learn' },
  'TH-2026-042': { status:'DCSync Staging · Active', statusClass:'chip-red', title:'Privileged Account Abuse & DCSync Staging — Tier-0 Assets', defaultTab:'learn' },
  'TH-2026-040': { status:'FIN7 Ransomware · Closed', statusClass:'chip-green', title:'Ransomware Pre-cursor BEC Activity — Finance Segment', defaultTab:'keep' },
  'TH-2026-039': { status:'Supply Chain · Closed', statusClass:'chip-green', title:'Supply Chain Compromise Indicators — DevOps Pipeline', defaultTab:'keep' },
};

// ── Subhunt sidebar ──
let activeSubhunt = 'all';

function renderSubhuntSidebar(huntId) {
  const keepId = huntId.replace('TH-2026-', '');
  const sidebar = document.getElementById('subhunt-sidebar');
  if (!sidebar) return;
  const d = keepData[keepId];
  if (!d || !d.subhunts || !d.subhunts.length) {
    sidebar.style.display = 'none';
    return;
  }
  sidebar.style.display = '';
  const dot = s => `<div class="sh-status-dot ${s}"></div>`;
  sidebar.innerHTML = `
    <div class="sh-section-label">Subhunts</div>
    <div class="sh-nav-item${activeSubhunt === 'all' ? ' on' : ''}" onclick="switchSubhunt('all')">
      <div class="sh-all-row"><div class="sh-all-dot"></div>All subhunts</div>
    </div>
    <div class="sh-divider"></div>
    ${d.subhunts.map(sh => `
      <div class="sh-nav-item${activeSubhunt === sh.id ? ' on' : ''}" onclick="switchSubhunt('${sh.id}')">
        <div class="sh-item-row">
          ${dot(sh.status)}
          <div>
            <div class="sh-label">${sh.label}</div>
            <div class="sh-ttp">${sh.ttp}</div>
            <div class="sh-name">${sh.name}</div>
          </div>
        </div>
      </div>`).join('')}`;
}

function switchSubhunt(id) {
  activeSubhunt = id;
  const huntId = document.getElementById('hd-id')?.textContent || '';
  renderSubhuntSidebar(huntId);
  const keepId = huntId.replace('TH-2026-', '');
  if (keepId) {
    renderGeneratedRulesCard();
    renderKeepHunt(keepId);
    if (typeof renderHuntObserve === 'function') renderHuntObserve(keepId);
    if (typeof renderRAAResults === 'function') renderRAAResults();
  }
}

function openHunt(id) {
  const m = huntMeta[id] || {};
  // Capture current sub-tab BEFORE any navigation changes the pane state
  const alreadyInDetail = document.getElementById('pane-hunt-detail')?.classList.contains('on');
  const preservedTab = alreadyInDetail
    ? (document.querySelector('.sub-tab.on')?.id?.replace('subtab-', '') || null)
    : null;

  // Reset subhunt selection when opening a hunt
  activeSubhunt = 'all';

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
  // Show/hide Run Pipeline button — only for active hunts with live animation (041)
  const pipelineBtn = document.getElementById('run-pipeline-btn');
  if (pipelineBtn) pipelineBtn.style.display = (m.status && m.status.includes('Closed')) ? 'none' : '';
  // Reset pipeline bar + feed to clean state before populating for this hunt
  if (typeof resetPipeline === 'function') resetPipeline();
  // Render observe data for this hunt
  const keepId = id.replace('TH-2026-', '');
  renderHuntObserve(keepId);
  // Don't preserve 'keep' tab for hunts with no Keep data (e.g., drafts) — redirect to their defaultTab
  const hasKeepData = !!keepData[keepId];
  const safePreserved = (preservedTab === 'keep' && !hasKeepData) ? null : preservedTab;
  const targetTab = safePreserved || m.defaultTab || 'learn';
  goSubTab(targetTab, document.getElementById('subtab-' + targetTab));
  // Render subhunt sidebar for this hunt — hide for active hunts
  // (pipeline animation or loadClosedPipeline reveals it later)
  renderSubhuntSidebar(id);
  if (!m.status || !m.status.includes('Closed')) {
    const sidebar = document.getElementById('subhunt-sidebar');
    if (sidebar) sidebar.style.display = 'none';
  }
  // Sync Keep sub-pane to the selected hunt
  switchKeepHunt(keepId);
  // Reset Check sub-pane for the new hunt
  resetCheckForHunt(id);
  // Load pipeline state and apply tab gating
  // For hunts with archived pipeline data: loadClosedPipeline sets pipelineLocked/maxStep
  // and calls updateSubTabGating with the correct state.
  // For 041 (live demo): tabs stay locked until runPipeline advances them.
  const hasArchivedPipeline = (m.status && m.status.includes('Closed')) || (typeof closedHuntFeeds !== 'undefined' && closedHuntFeeds[keepId]);
  if (hasArchivedPipeline && typeof loadClosedPipeline === 'function') {
    loadClosedPipeline(id, keepId);
  } else {
    updateSubTabGating();
  }
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

// ── FAQ search filter ──
function filterCompletedHunts(q) {
  const term = q.toLowerCase().trim();
  document.querySelectorAll('.completed-hunts-table tbody tr').forEach(row => {
    row.style.display = term === '' || row.textContent.toLowerCase().includes(term) ? '' : 'none';
  });
}

function filterFaq(q) {
  const term = q.toLowerCase().trim();
  // Show/hide individual FAQ items
  document.querySelectorAll('.faq-item').forEach(item => {
    const match = term === '' || item.textContent.toLowerCase().includes(term);
    item.classList.toggle('faq-hidden', !match);
  });
  // Hide category labels that have no visible items beneath them
  document.querySelectorAll('.faq-cat-label').forEach(label => {
    if (term === '') { label.classList.remove('faq-hidden'); return; }
    let sibling = label.nextElementSibling;
    let hasVisible = false;
    while (sibling && !sibling.classList.contains('faq-cat-label')) {
      if (!sibling.classList.contains('faq-hidden')) { hasVisible = true; break; }
      sibling = sibling.nextElementSibling;
    }
    label.classList.toggle('faq-hidden', !hasVisible);
  });
}

// ── Intelligence Repository ──
const repoData = [
  { id: 'r1', icon: '🇺🇸', title: 'CISA AA24-038A — Volt Typhoon', source: 'CISA', actor: 'Volt Typhoon', date: '2024-02-07', ttps: 8, tags: ['APT', 'ICS/OT', 'Living off the Land'], techniques: ['T1078.002','T1570','T1003.001','T1558.003','T1071.001','T1547.001','T1053.005','T1041'] },
  { id: 'r2', icon: '🔴', title: 'Mandiant APT41 — Dual Espionage & Crimeware', source: 'Mandiant', actor: 'APT41', date: '2023-11-14', ttps: 5, tags: ['APT', 'Ransomware', 'Supply Chain'], techniques: ['T1195.002','T1059.001','T1055','T1486','T1562.001'] },
  { id: 'r3', icon: '🇰🇵', title: 'Lazarus Group — 3CX Supply Chain Attack', source: 'CrowdStrike', actor: 'Lazarus Group', date: '2023-04-20', ttps: 5, tags: ['Supply Chain', 'macOS', 'Windows'], techniques: ['T1195.002','T1547.001','T1059.004','T1071.001','T1041'] },
  { id: 'r4', icon: '🐻', title: 'FANCY BEAR — Credential Harvest Campaign', source: 'Recorded Future', actor: 'FANCY BEAR', date: '2024-01-09', ttps: 5, tags: ['APT', 'Phishing', 'Credential Access'], techniques: ['T1566.001','T1078','T1003','T1558','T1071'] },
  { id: 'r5', icon: '🕷️', title: 'SCATTERED SPIDER — Social Engineering TTPs', source: 'CISA', actor: 'SCATTERED SPIDER', date: '2023-11-16', ttps: 5, tags: ['Social Engineering', 'MFA Bypass', 'Cloud'], techniques: ['T1566','T1621','T1078.004','T1530','T1657'] },
  { id: 'r6', icon: '🇷🇺', title: 'Sandworm — Ukraine Power Grid Intrusion', source: 'ESET', actor: 'Sandworm', date: '2023-12-21', ttps: 5, tags: ['ICS/OT', 'Destructive', 'Ukraine'], techniques: ['T1078','T1059','T1485','T1565.003','T1498'] },
  { id: 'r7', icon: '💎', title: 'BlackCat/ALPHV — Healthcare Sector Targeting', source: 'HHS HC3', actor: 'BlackCat/ALPHV', date: '2024-02-27', ttps: 5, tags: ['Ransomware', 'Healthcare', 'Double Extortion'], techniques: ['T1486','T1490','T1070','T1078','T1071.001'] },
];

// ── Per-report TTP detail rows (drives Stage 1 table) ──
const reportTTPDetails = {
  'r1': [
    { id:'T1078.002', name:'Valid Accounts: Domain',      detail:null, tactic:'Def. Evasion', tacticClass:'chip-yellow', prior:3, rules:'2 live',  rulesColor:'green',  sid:'s01' },
    { id:'T1570',     name:'Lateral Tool Transfer',       detail:'Confirmed in TH-2026-038 · jsmith pivot chain scoped', tactic:'Lateral Mvmt', tacticClass:'chip-red',    prior:2, rules:'2 live',  rulesColor:'green',  sid:'s02' },
    { id:'T1003.001', name:'LSASS Credential Dumping',    detail:'Follows lateral movement to WIN-DC01 · SK-029 exclusion list pre-loaded', tactic:'Cred. Access',  tacticClass:'chip-red',    prior:2, rules:'1 live',  rulesColor:'yellow', sid:'s04' },
    { id:'T1558.003', name:'Kerberoasting',               detail:'147 SPN exclusions loaded · RC4 threshold tuned to >3 SPNs/user/5m · FP rate <2%', tactic:'Cred. Access',  tacticClass:'chip-red',    prior:2, rules:'1 tuned', rulesColor:'yellow', sid:'s05' },
    { id:'T1071.001', name:'C2 Beacon via HTTPS',         detail:'Net-new cert-chain path · JA3 fingerprint detection available', tactic:'C&C',          tacticClass:'chip-indigo', prior:3, rules:'1 live',  rulesColor:'yellow', sid:'s06' },
    { id:'T1547.001', name:'Registry Run Keys',           detail:null, tactic:'Persistence',   tacticClass:'chip-indigo', prior:1, rules:'1 live',  rulesColor:'yellow', sid:'s08' },
    { id:'T1053.005', name:'Scheduled Task',              detail:null, tactic:'Persistence',   tacticClass:'chip-indigo', prior:1, rules:'1 live',  rulesColor:'yellow', sid:'s08' },
    { id:'T1041',     name:'Exfil Over C2 Channel',       detail:null, tactic:'Exfiltration',  tacticClass:'chip-red',    prior:0, rules:'none',    rulesColor:'muted',  sid:'s07' },
  ],
  'r2': [
    { id:'T1195.002', name:'Supply Chain Compromise',     detail:null, tactic:'Initial Access', tacticClass:'chip-red',    prior:0, rules:'none',    rulesColor:'muted',  sid:null },
    { id:'T1059.001', name:'PowerShell Execution',        detail:null, tactic:'Execution',      tacticClass:'chip-yellow', prior:2, rules:'2 live',  rulesColor:'green',  sid:null },
    { id:'T1055',     name:'Process Injection',           detail:null, tactic:'Def. Evasion',   tacticClass:'chip-yellow', prior:1, rules:'1 live',  rulesColor:'yellow', sid:null },
    { id:'T1486',     name:'Data Encrypted for Impact',   detail:null, tactic:'Impact',         tacticClass:'chip-red',    prior:0, rules:'none',    rulesColor:'muted',  sid:null },
    { id:'T1562.001', name:'Disable Security Tools',      detail:null, tactic:'Def. Evasion',   tacticClass:'chip-yellow', prior:1, rules:'1 live',  rulesColor:'yellow', sid:null },
  ],
  'r3': [
    { id:'T1195.002', name:'Supply Chain Compromise',     detail:null, tactic:'Initial Access', tacticClass:'chip-red',    prior:0, rules:'none',    rulesColor:'muted',  sid:null },
    { id:'T1547.001', name:'Registry Run Keys / Startup', detail:null, tactic:'Persistence',   tacticClass:'chip-indigo', prior:1, rules:'1 live',  rulesColor:'yellow', sid:null },
    { id:'T1059.004', name:'Unix Shell Execution',        detail:null, tactic:'Execution',      tacticClass:'chip-yellow', prior:0, rules:'none',    rulesColor:'muted',  sid:null },
    { id:'T1071.001', name:'C2 Beacon via HTTPS',         detail:null, tactic:'C&C',            tacticClass:'chip-indigo', prior:2, rules:'1 live',  rulesColor:'yellow', sid:null },
    { id:'T1041',     name:'Exfil Over C2 Channel',       detail:null, tactic:'Exfiltration',   tacticClass:'chip-red',    prior:0, rules:'none',    rulesColor:'muted',  sid:null },
  ],
  'r4': [
    { id:'T1566.001', name:'Spearphishing Attachment',    detail:null, tactic:'Initial Access', tacticClass:'chip-red',    prior:1, rules:'1 live',  rulesColor:'yellow', sid:null },
    { id:'T1078',     name:'Valid Accounts',              detail:null, tactic:'Def. Evasion',   tacticClass:'chip-yellow', prior:2, rules:'2 live',  rulesColor:'green',  sid:null },
    { id:'T1003',     name:'Credential Dumping',          detail:null, tactic:'Cred. Access',   tacticClass:'chip-red',    prior:1, rules:'1 live',  rulesColor:'yellow', sid:null },
    { id:'T1558',     name:'Steal Kerberos Tickets',      detail:null, tactic:'Cred. Access',   tacticClass:'chip-red',    prior:1, rules:'1 tuned', rulesColor:'yellow', sid:null },
    { id:'T1071',     name:'C2 via App Layer Protocol',   detail:null, tactic:'C&C',            tacticClass:'chip-indigo', prior:1, rules:'1 live',  rulesColor:'yellow', sid:null },
  ],
  'r5': [
    { id:'T1566',     name:'Phishing',                    detail:null, tactic:'Initial Access', tacticClass:'chip-red',    prior:1, rules:'1 live',  rulesColor:'yellow', sid:null },
    { id:'T1621',     name:'MFA Request Generation',      detail:null, tactic:'Cred. Access',   tacticClass:'chip-red',    prior:0, rules:'none',    rulesColor:'muted',  sid:null },
    { id:'T1078.004', name:'Valid Cloud Accounts',        detail:null, tactic:'Def. Evasion',   tacticClass:'chip-yellow', prior:0, rules:'none',    rulesColor:'muted',  sid:null },
    { id:'T1530',     name:'Data from Cloud Storage',     detail:null, tactic:'Collection',     tacticClass:'chip-indigo', prior:0, rules:'none',    rulesColor:'muted',  sid:null },
    { id:'T1657',     name:'Financial Theft',             detail:null, tactic:'Impact',         tacticClass:'chip-red',    prior:0, rules:'none',    rulesColor:'muted',  sid:null },
  ],
  'r6': [
    { id:'T1078',     name:'Valid Accounts',              detail:null, tactic:'Def. Evasion',   tacticClass:'chip-yellow', prior:2, rules:'2 live',  rulesColor:'green',  sid:null },
    { id:'T1059',     name:'Command & Scripting Interp.', detail:null, tactic:'Execution',      tacticClass:'chip-yellow', prior:1, rules:'1 live',  rulesColor:'yellow', sid:null },
    { id:'T1485',     name:'Data Destruction',            detail:null, tactic:'Impact',         tacticClass:'chip-red',    prior:0, rules:'none',    rulesColor:'muted',  sid:null },
    { id:'T1565.003', name:'Runtime Data Manipulation',   detail:null, tactic:'Impact',         tacticClass:'chip-red',    prior:0, rules:'none',    rulesColor:'muted',  sid:null },
    { id:'T1498',     name:'Network DoS',                 detail:null, tactic:'Impact',         tacticClass:'chip-red',    prior:0, rules:'none',    rulesColor:'muted',  sid:null },
  ],
  'r7': [
    { id:'T1486',     name:'Data Encrypted for Impact',   detail:null, tactic:'Impact',         tacticClass:'chip-red',    prior:0, rules:'none',    rulesColor:'muted',  sid:null },
    { id:'T1490',     name:'Inhibit System Recovery',     detail:null, tactic:'Impact',         tacticClass:'chip-red',    prior:0, rules:'none',    rulesColor:'muted',  sid:null },
    { id:'T1070',     name:'Indicator Removal',           detail:null, tactic:'Def. Evasion',   tacticClass:'chip-yellow', prior:1, rules:'1 live',  rulesColor:'yellow', sid:null },
    { id:'T1078',     name:'Valid Accounts',              detail:null, tactic:'Def. Evasion',   tacticClass:'chip-yellow', prior:2, rules:'2 live',  rulesColor:'green',  sid:null },
    { id:'T1071.001', name:'C2 Beacon via HTTPS',         detail:null, tactic:'C&C',            tacticClass:'chip-indigo', prior:1, rules:'1 live',  rulesColor:'yellow', sid:null },
  ],
};

// ── Analyst TTP selection (set in Stage 1) ──
let selectedTTPIds = new Set();

function renderTTPTable(reportId) {
  const tbody = document.getElementById('ttp-tbody');
  if (!tbody) return;
  const rows = reportTTPDetails[reportId] || [];
  selectedTTPIds = new Set();
  tbody.innerHTML = rows.map(t => {
    const safeId = t.id.replace(/\./g, '_');
    const priorColor = t.prior > 1 ? 'green' : t.prior === 1 ? 'yellow' : 'muted';
    return `<tr class="ttp-row-selectable" id="ttp-row-${safeId}" onclick="toggleTTPRow('${t.id}')">
      <td class="ttp-sel-col"><span class="ttp-chk" id="ttp-chk-${safeId}">☐</span></td>
      <td class="ttp-id">${t.id}</td>
      <td>${t.name}${t.detail ? `<div style="font-size:10px;color:var(--blue);margin-top:2px;">${t.detail}</div>` : ''}</td>
      <td><span class="chip ${t.tacticClass}" style="font-size:9px;">${t.tactic}</span></td>
      <td style="font-size:11px;color:var(--${priorColor});font-weight:600;">${t.prior}</td>
      <td style="font-size:11px;color:var(--${t.rulesColor});font-weight:600;">${t.rules}</td>
      ${t.sid ? `<td><span class="sent-badge" data-sid="${t.sid}">${t.sid.toUpperCase()}</span></td>` : '<td style="color:var(--muted);font-size:11px;">—</td>'}
    </tr>`;
  }).join('');
  updateTTPSelectionUI();
}

function toggleTTPRow(ttpId) {
  if (selectedTTPIds.has(ttpId)) {
    selectedTTPIds.delete(ttpId);
  } else {
    selectedTTPIds.add(ttpId);
  }
  const safeId = ttpId.replace(/\./g, '_');
  const row = document.getElementById('ttp-row-' + safeId);
  if (row) row.classList.toggle('ttp-row-selected', selectedTTPIds.has(ttpId));
  const chk = document.getElementById('ttp-chk-' + safeId);
  if (chk) chk.textContent = selectedTTPIds.has(ttpId) ? '☑' : '☐';
  updateTTPSelectionUI();
}

function updateTTPSelectionUI() {
  const n     = selectedTTPIds.size;
  const total = (reportTTPDetails[activeReportId] || []).length;
  const chips = document.getElementById('stage1-report-chips');
  if (chips) {
    chips.innerHTML = `<span class="chip chip-blue">${total} extracted</span>`
      + (n > 0 ? `<span class="chip chip-green">${n} selected</span>` : `<span class="chip chip-gray" style="font-size:10px;">none selected</span>`)
      + `<span class="chip chip-indigo">ATT&amp;CK v14</span>`;
  }
  const btn = document.getElementById('ttp-confirm-btn');
  if (btn) {
    btn.disabled  = n === 0;
    btn.style.opacity = n === 0 ? '0.4' : '';
    btn.style.cursor  = n === 0 ? 'not-allowed' : '';
    btn.textContent   = n > 0
      ? `Generate Hypotheses for ${n} TTP${n !== 1 ? 's' : ''} →`
      : 'Select TTPs to continue →';
  }
}

function confirmTTPSelection() {
  if (selectedTTPIds.size === 0) return;
  const n     = selectedTTPIds.size;
  const total = (reportTTPDetails[activeReportId] || []).length;
  const lhcTtps = document.getElementById('lhc-ttps');
  if (lhcTtps) lhcTtps.textContent = total + ' extracted · ' + n + ' selected';
  renderHypothesisAgentCard();
  renderHypothesisBranchRows();
  renderHypothesisCards();
  updateRefDataBanner();
  setStep(2);
}

// ── Dynamic Stage-2 rendering (hypothesis agent card, branch rows, hypothesis cards) ──

function renderHypothesisAgentCard() {
  const el = document.getElementById('hyp-agent-reasoning');
  if (!el) return;
  const r = repoData.find(x => x.id === activeReportId);
  if (!r) return;

  const allTTPs    = reportTTPDetails[activeReportId] || [];
  const selArr     = allTTPs.filter(t => selectedTTPIds.has(t.id));
  const highConf   = selArr.filter(t => t.prior >= 1);
  const pastCount  = selArr.reduce((s, t) => s + t.prior, 0);
  const confIds    = highConf.map(t => t.id);

  let ttpList;
  if (confIds.length === 0)       ttpList = 'none carry prior confirmation';
  else if (confIds.length === 1)  ttpList = confIds[0];
  else ttpList = confIds.slice(0, -1).join(', ') + ', and ' + confIds[confIds.length - 1];

  let text;
  if (highConf.length > 0) {
    text = `I've analysed the ${allTTPs.length} TTPs from ${r.title} and cross-referenced ${pastCount} past hunt${pastCount !== 1 ? 's' : ''} via the Past Hunts tool. `
         + `${highConf.length} technique${highConf.length !== 1 ? 's' : ''} carry high confidence and prior confirmation — ${ttpList} — matched to prior activity in recent hunts. `
         + `I recommend scoping hypothesis generation to these ${highConf.length} technique${highConf.length !== 1 ? 's' : ''} first. `
         + `The remaining ${selArr.length - highConf.length} are retained as secondary indicators and can be promoted to primary scope at any time.`;
  } else {
    text = `I've analysed the ${allTTPs.length} TTPs from ${r.title} and cross-referenced past hunts via the Past Hunts tool. `
         + `No prior confirmations found for the ${selArr.length} selected technique${selArr.length !== 1 ? 's' : ''} — all are net-new. `
         + `I recommend generating hypotheses for all ${selArr.length} selected technique${selArr.length !== 1 ? 's' : ''} with baseline confidence. `
         + `Prior hunt context will be gathered during the Observe phase.`;
  }
  el.textContent = text;

  // Update gate modify panel radio options to match current selection
  const allTTPsCount = allTTPs.length;
  const highIds = highConf.length ? highConf.map(t => t.id).join(', ') : selArr.map(t => t.id).join(', ');
  const allSelIds = selArr.map(t => t.id).join(', ');
  const panel = document.getElementById('gate-1-modify');
  if (panel) {
    const opts = panel.querySelectorAll('.gate-option');
    if (opts.length >= 3) {
      const highN = highConf.length || selArr.length;
      opts[0].innerHTML = `<input type="radio" name="g1-scope" checked> Analyst selection — ${highIds} <span style="color:var(--muted);">(${highN} TTP${highN !== 1 ? 's' : ''})</span>`;
      opts[1].innerHTML = `<input type="radio" name="g1-scope"> All selected TTPs — ${allSelIds} <span style="color:var(--muted);">(${selArr.length} TTP${selArr.length !== 1 ? 's' : ''})</span>`;
      opts[2].innerHTML = `<input type="radio" name="g1-scope"> All extracted TTPs from report <span style="color:var(--muted);">(${allTTPsCount} TTP${allTTPsCount !== 1 ? 's' : ''})</span>`;
    }
  }
}

function renderHypothesisBranchRows() {
  const wrap = document.getElementById('hyp-branch-wrap');
  if (!wrap) return;

  const allTTPs  = reportTTPDetails[activeReportId] || [];
  const selArr   = allTTPs.filter(t => selectedTTPIds.has(t.id)).sort((a, b) => b.prior - a.prior);
  if (selArr.length === 0) { wrap.innerHTML = ''; return; }

  const tactCtx = {
    'Lateral Mvmt':   { desc:'pivot chain pattern',                    action:'host-hop threshold pre-applied · segment scope set' },
    'Cred. Access':   { desc:'credential access on high-value host',   action:'exclusion list pre-loaded · process filter applied' },
    'C&C':            { desc:'beacon interval anomaly in egress',       action:'JA3 hash list loaded · beacon stdev threshold set' },
    'Persistence':    { desc:'persistence artifact detected',           action:'known-good baseline exclusions applied' },
    'Def. Evasion':   { desc:'security tooling interference noted',     action:'baseline-deviation threshold tuned' },
    'Initial Access': { desc:'initial access indicator identified',     action:'net-new detection path scoped' },
    'Execution':      { desc:'script interpreter invocation chain',     action:'LOLBin filter and parent-process chain applied' },
    'Exfiltration':   { desc:'unusual outbound volume pattern',         action:'egress baseline applied · destination scoring enabled' },
    'Impact':         { desc:'destructive artifact identified',         action:'critical asset scope pre-applied' },
    'Collection':     { desc:'cloud storage access pattern',            action:'identity-based access scope applied' },
  };
  const huntRefs = ['TH-2026-038', 'TH-2025-091', 'TH-2025-087', 'TH-2025-079', 'TH-2026-035'];

  wrap.innerHTML = selArr.map((t, i) => {
    const hNum  = `H-0${i + 1}`;
    const ctx   = tactCtx[t.tactic] || { desc:'technique pattern noted', action:'scope and threshold pre-applied' };
    let icon, labelClass, labelText, huntRef, bodyText, actionText;

    if (t.prior >= 2) {
      icon = '🎯'; labelClass = 'hbl-confirmed'; labelText = 'Confirmed';
      huntRef  = huntRefs[i % huntRefs.length];
      bodyText = `${t.name} — ${ctx.desc} confirmed in prior hunt · ${t.prior} hunt${t.prior !== 1 ? 's' : ''} with matching activity detected in this environment.`;
      actionText = `↳ Confidence elevated to High · ${ctx.action}`;
    } else if (t.prior === 1) {
      const isFP = (i % 2 === 1);
      icon = isFP ? '🔔' : '❄️'; labelClass = isFP ? 'hbl-fp' : 'hbl-clean';
      labelText = isFP ? 'FPs in prior run' : 'Clean prior run';
      huntRef  = huntRefs[(i + 2) % huntRefs.length];
      bodyText = isFP
        ? `${t.name} — ${ctx.desc} showed elevated FP rate in prior run. Signal recoverable with tuning parameters pre-applied.`
        : `${t.name} — ${ctx.desc} returned no hits in prior run. Technique variant possible or threat actor was not active at hunt time.`;
      actionText = `↳ ${ctx.action} · confidence Medium`;
    } else {
      icon = '🔵'; labelClass = ''; labelText = 'Net-new'; huntRef = '';
      bodyText = `${t.name} — no prior hunt data available for this environment. First time this technique has been in scope.`;
      actionText = `↳ Baseline detection path scoped from CTI report · confidence Low`;
    }

    return `<div class="hyp-branch-row">
      <div class="hyp-branch-top">
        <span class="hyp-branch-num">${hNum}</span>
        <span class="hyp-branch-icon">${icon}</span>
        <span class="hyp-branch-label${labelClass ? ' ' + labelClass : ''}">${labelText}</span>
        ${huntRef ? `<span class="hyp-branch-hunt">${huntRef}</span>` : ''}
      </div>
      <div class="hyp-branch-body">${bodyText}</div>
      <div class="hyp-branch-action">${actionText}</div>
    </div>`;
  }).join('');
}

function renderHypothesisCards() {
  const wrap = document.getElementById('hyp-cards-main');
  if (!wrap) return;

  const allTTPs = reportTTPDetails[activeReportId] || [];
  const selArr  = allTTPs.filter(t => selectedTTPIds.has(t.id)).sort((a, b) => b.prior - a.prior);
  if (selArr.length === 0) { wrap.innerHTML = ''; return; }

  const stmtFn = {
    'Lateral Mvmt':   t => `Adversary is performing lateral movement via ${t.name} targeting high-value systems within the network.`,
    'Cred. Access':   t => `Attacker is harvesting credentials using ${t.name} from high-value hosts following initial compromise.`,
    'C&C':            t => `A C2 implant is maintaining communications via ${t.name}, identified through beacon interval and traffic anomalies.`,
    'Persistence':    t => `Adversary has established persistence via ${t.name} on targeted endpoints to survive defensive actions.`,
    'Def. Evasion':   t => `Adversary is evading defenses via ${t.name} to maintain access without triggering deployed analytics.`,
    'Initial Access': t => `Adversary gained initial access via ${t.name} targeting users or supplier systems in this environment.`,
    'Execution':      t => `Adversary is executing code via ${t.name} to deploy and run payloads on compromised endpoints.`,
    'Exfiltration':   t => `Adversary is exfiltrating collected data via ${t.name} over the established command channel.`,
    'Impact':         t => `Adversary is executing an impact operation via ${t.name} against critical data or infrastructure assets.`,
    'Collection':     t => `Adversary is collecting sensitive data via ${t.name} from enterprise or cloud storage resources.`,
  };
  const ratFn = {
    'Lateral Mvmt':   t => `CTI report documents ${t.id} usage. ${t.prior >= 1 ? `${t.prior} prior hunt${t.prior !== 1 ? 's' : ''} with confirmed activity — pivot chain scope pre-applied.` : 'Net-new technique — host-hop baseline detection path scoped.'}`,
    'Cred. Access':   t => `${t.prior >= 1 ? `Prior hunt data available — ${t.rules} deployed.` : 'No prior hunt data.'} Exclusion list pre-loaded to reduce FP rate. Scoped to high-value hosts.`,
    'C&C':            t => `${t.prior >= 1 ? 'Prior hunt signal available.' : 'Net-new detection path.'} JA3 fingerprint and beacon interval analysis enabled. Cert-chain anomaly path also scoped.`,
    'Persistence':    t => `${t.prior >= 1 ? `${t.prior} prior hunt${t.prior !== 1 ? 's' : ''} — known-good baseline loaded.` : 'No prior data — baseline being established.'} Registry and scheduled task artifacts in scope.`,
    'Def. Evasion':   t => `${t.prior >= 1 ? 'Prior hunt flagged this technique.' : 'Net-new evasion path.'} Security tooling interference pattern scoped. Baseline-deviation threshold applied.`,
    'Initial Access': t => `CTI report identifies ${t.id} as entry vector. ${t.prior >= 1 ? 'Prior data available — signal tuning applied.' : 'Net-new — baseline detection path scoped.'}`,
    'Execution':      t => `${t.prior >= 1 ? `${t.prior} prior hunt${t.prior !== 1 ? 's' : ''} confirmed activity.` : 'No prior data.'} Parent-process chain and LOLBin filter applied. Script interpreter scope set.`,
    'Exfiltration':   t => `${t.prior >= 1 ? 'Prior hunt data available.' : 'Net-new path.'} Egress baseline applied. Destination scoring and volume anomaly threshold set.`,
    'Impact':         t => `${t.prior >= 1 ? 'Prior hunt data available.' : 'Net-new impact path — no prior hunt data.'} Critical asset scope pre-applied. Destructive artifact pattern scoped.`,
    'Collection':     t => `${t.prior >= 1 ? 'Prior hunt flagged cloud access pattern.' : 'Net-new — first time in scope.'} Identity-based scope applied.`,
  };
  const defaultStmt = t => `Adversary technique ${t.id} (${t.name}) detected in environment — hypothesis scoped from CTI report.`;
  const defaultRat  = t => `Prior hunt data: ${t.prior} hunt${t.prior !== 1 ? 's' : ''}. Rules: ${t.rules}. Detection path scoped from CTI advisory.`;

  wrap.innerHTML = selArr.map((t, i) => {
    const hNum      = `H-0${i + 1}`;
    const confClass = t.prior >= 2 ? 'chip-yellow' : t.prior === 1 ? 'chip-blue' : 'chip-gray';
    const confText  = t.prior >= 2 ? 'High confidence' : t.prior === 1 ? 'Medium confidence' : 'Low confidence';
    const ttpChip   = ['chip-red','chip-orange'].includes(t.tacticClass) ? 'chip-red' : t.tacticClass;
    const selCls    = i === 0 ? ' sel' : '';
    const stmt      = (stmtFn[t.tactic] || defaultStmt)(t);
    const rat       = (ratFn[t.tactic]  || defaultRat)(t);
    return `<div class="hyp-card${selCls}" onclick="selHyp(this)">
      <div class="hyp-head"><span class="hyp-num">${hNum}</span><div class="hyp-text">${stmt}</div></div>
      <div class="hyp-meta"><span class="chip ${ttpChip}" style="font-size:10px;">${t.id}</span><span class="chip ${confClass}" style="font-size:10px;">${confText}</span></div>
      <div class="hyp-rationale">${rat}</div>
    </div>`;
  }).join('');
}

function updateRefDataBanner() {
  const isNonR1 = activeReportId && activeReportId !== 'r1';
  const r = isNonR1 ? repoData.find(x => x.id === activeReportId) : null;
  const msg = r
    ? `<span class="ib-icon">📋</span><span><b>Reference view</b> — Observe, Check, and Keep panels show data from the reference Volt Typhoon hunt (TH-2026-041). Findings for <b>${r.title}</b> will populate here once detections are run with your selected TTPs.</span>`
    : '';
  ['ref-data-banner-observe', 'ref-data-banner-check', 'ref-data-banner-keep'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.style.display = isNonR1 ? '' : 'none';
    if (isNonR1) el.innerHTML = msg;
  });
}

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
    // Render selectable TTP table (no pre-selection) + sentence evidence panel
    renderTTPTable(id);
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

  // Only the primary demo hunt (041) has live pipeline animation data.
  // Other hunts load via loadClosedPipeline — don't re-run the 041 animation.
  const currentHunt = document.getElementById('hd-id')?.textContent || '';
  if (currentHunt !== 'TH-2026-041') return;

  // Disable button during run
  btn.disabled = true;
  btn.textContent = '⏳ Running…';

  // Select the CTI report — this triggers step 0→1, populates TTPs, and starts the feed.
  // selectReport handles its own 400ms delay for TTP rendering, so we offset all
  // subsequent stage advances relative to that baseline.
  selectReport('r1');

  const tsPill = document.getElementById('ts-pill');
  const dlPill = document.getElementById('dl-pill');
  if (tsPill) tsPill.style.opacity = '0.4';
  if (dlPill) dlPill.style.opacity = '0.4';

  const scrollToStage = (id) => {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  // Advance through stages 2-4 with delays (stage 0→1 is handled by selectReport).
  const steps = [
    { delay: 22000, step: 2, stage: 'stage-2' },
    { delay: 40000, step: 3, stage: 'stage-3' },
    { delay: 74000, step: 4, stage: 'stage-4' },
  ];

  steps.forEach(({ delay, step, stage }) => {
    setTimeout(() => {
      setStep(step);
      scrollToStage(stage);
    }, delay);
  });

  // Re-enable button after full run (~87s for all 5 steps)
  setTimeout(() => {
    btn.disabled = false;
    btn.textContent = '▶ Run Pipeline';
  }, 90000);
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

/* ── Model card ─────────────────────────────────────────────── */
let agentModels = { orch:'', hyp:'', data:'', ts:'', dl:'' };

function toggleModelCard() {
  const body = document.getElementById('model-card-body');
  const chev = document.getElementById('model-card-chev');
  if (!body) return;
  const collapsed = body.style.display === 'none';
  body.style.display = collapsed ? '' : 'none';
  if (chev) chev.textContent = collapsed ? '▾' : '▸';
}

function setAgentModel(agent, val) {
  agentModels[agent] = val;
  const sel = document.getElementById('amod-' + agent);
  if (sel) sel.classList.toggle('overridden', val !== '');
}

function selectModel(el, name, meta) {
  document.querySelectorAll('.model-menu-item').forEach(i => i.classList.remove('active-model'));
  el.classList.add('active-model');
  const lbl = document.getElementById('model-badge-label');
  if (lbl) lbl.textContent = name;
  // Update the "Global" placeholder text in every agent override select
  const shortName = name.replace('Llama ', 'Llama ').replace('Mixtral ', 'Mixtral ');
  document.querySelectorAll('.agent-model-select option[value=""]').forEach(opt => {
    opt.textContent = `↳ Global (${shortName})`;
  });
}

function toggleUserMenu() {
  document.getElementById('user-menu').classList.toggle('open');
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
});


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
    { id:'s07', text:'Data is exfiltrated through the established C2 channel, avoiding dedicated exfiltration tools to minimise the forensic artifact footprint and reduce network anomaly signatures.' },
    { id:'s08', text:'Actors establish persistence via scheduled tasks and registry Run keys, using names that mimic legitimate software entries (e.g. MicrosoftEdgeUpdate) to blend with environment baseline.' },
  ],
  'r2': [
    { id:'s01', text:'APT41 gains initial access via supply chain compromise, inserting malicious code into trusted software build environments to distribute implants via legitimate update channels.' },
    { id:'s02', text:'The group executes payloads through PowerShell and WMI to run code in-memory, avoiding disk-based artifacts that would be detected by endpoint security tools.' },
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
      <div class="report-kv"><span class="report-kv-k">Threat Actor</span><span class="report-kv-v">Volt Typhoon</span></div>
      <div class="report-kv"><span class="report-kv-k">CTI Source</span><span class="report-kv-v">CISA AA24-038A — Volt Typhoon</span></div>
      <div class="report-kv"><span class="report-kv-k">Environment</span><span class="report-kv-v">Splunk ES · Corp domain · index=sysmon, wineventlog, network</span></div>
      <div class="report-kv"><span class="report-kv-k">Status</span><span class="report-kv-v">Active — 4 detection rules deployed, IR escalation recommended</span></div>
    </div>

    <div class="report-section">
      <div class="report-sh">TTPs Investigated (4 selected of 8 extracted)</div>
      <div class="report-row"><span class="chip chip-red" style="font-size:9px;">T1570</span><span style="flex:1;">Lateral Tool Transfer / PsExec</span><span style="font-size:10px;color:var(--green);">Confirmed · 14 hits</span></div>
      <div class="report-row"><span class="chip chip-red" style="font-size:9px;">T1003.001</span><span style="flex:1;">LSASS Memory Access — WIN-DC01</span><span style="font-size:10px;color:var(--green);">Confirmed · 1 critical hit</span></div>
      <div class="report-row"><span class="chip chip-red" style="font-size:9px;">T1558.003</span><span style="flex:1;">Kerberoasting — Anomalous TGS-REQ</span><span style="font-size:10px;color:var(--green);">Confirmed · 3 bursts (11 SPNs)</span></div>
      <div class="report-row"><span class="chip chip-yellow" style="font-size:9px;">T1071.001</span><span style="flex:1;">C2 Beacon via HTTPS — JA3 match</span><span style="font-size:10px;color:var(--green);">Confirmed · 2 sessions</span></div>
    </div>

    <div class="report-section">
      <div class="report-sh">Detection Rules Created (4)</div>
      <div class="report-rule-block">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
          <span class="chip chip-red" style="font-size:9px;">T1570</span>
          <span style="font-weight:600;">PsExec Lateral Tool Transfer — ADMIN$ drop + service install</span>
        </div>
        <div style="color:var(--muted);font-size:10px;">DL-2026-041-001 · index=windows EventCode=5145 joined with 7045 · SCCM hosts 10.0.5.20/21 excluded · FP 1.4%</div>
      </div>
      <div class="report-rule-block">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
          <span class="chip chip-red" style="font-size:9px;">T1003.001</span>
          <span style="font-weight:600;">LSASS Memory Access — full-access handle (SK-029)</span>
        </div>
        <div style="color:var(--muted);font-size:10px;">DL-2026-041-002 · index=sysmon EventCode=10 · GrantedAccess=0x1fffff · MsMpEng/CrowdStrike/SentinelOne excluded · FP 0.9%</div>
      </div>
      <div class="report-rule-block">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
          <span class="chip chip-red" style="font-size:9px;">T1558.003</span>
          <span style="font-weight:600;">Kerberoasting — RC4 TGS-REQ Volume (SK-038)</span>
        </div>
        <div style="color:var(--muted);font-size:10px;">DL-2026-041-003 · index=wineventlog EventCode=4769 EncryptionType=0x17 · >3 SPNs/user/5m · BackupExec/MSSQLSvc excluded · FP 0.4%</div>
      </div>
      <div class="report-rule-block">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
          <span class="chip chip-yellow" style="font-size:9px;">T1071.001</span>
          <span style="font-weight:600;">C2 Beacon — JA3 fingerprint + interval regularity</span>
        </div>
        <div style="color:var(--muted);font-size:10px;">DL-2026-041-004 · index=network sourcetype=zeek:ssl · known CS JA3 hashes · stddev&lt;5s AND ≥8 conn/30m · FP 0.2%</div>
      </div>
    </div>

    <div class="report-section">
      <div class="report-sh">RAA Corroboration (2 analytics triggered)</div>
      <div class="report-row"><span class="chip chip-green" style="font-size:9px;">T1570</span><span style="flex:1;">Command Line Anomaly — jsmith pivot chain</span><span style="font-size:10px;color:var(--green);">59 hits</span></div>
      <div class="report-row"><span class="chip chip-green" style="font-size:9px;">T1003.001</span><span style="flex:1;">Process Chain Anomaly — rundll32→LSASS on WIN-DC01</span><span style="font-size:10px;color:var(--green);">Confirmed</span></div>
    </div>

    <div class="report-section">
      <div class="report-sh">Evidence Captured (${evidenceItems.length})</div>
      ${evSection}
    </div>

    <div class="report-section">
      <div class="report-sh">Recommendations</div>
      <div style="font-size:11px;color:var(--sub);display:flex;flex-direction:column;gap:6px;line-height:1.6;">
        <div>• Escalate to Incident Response immediately — isolate WIN-DC01 and acquire a memory image before reboot.</div>
        <div>• Suspend CORP\\jsmith and rotate all credentials authenticated from that account in the past 72 hours.</div>
        <div>• Push perimeter block for 185.220.101.47/32 and audit outbound port 443 for matching Cobalt Strike JA3 hashes.</div>
        <div>• Schedule follow-up hunt TH-2026-042 (privileged account abuse / DCSync staging) seeded with the confirmed jsmith pivot chain.</div>
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
  // KB tab rules
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
  },
  // Check stage subhunt rules — TH-2026-041
  'ck-t1570': {
    execTime:'1.1s', count:14,
    cols:['_time','host','src_ip','Account','svc_file'],
    riskCol:-1,
    rows:[
      ['03:14:07','WIN-WS089','10.10.14.22','CORP\\jsmith','psexesvc.exe'],
      ['03:14:09','WIN-WS102','10.10.14.22','CORP\\jsmith','psexesvc.exe'],
      ['03:14:11','WIN-DC01','10.10.14.22','CORP\\jsmith','psexesvc.exe'],
      ['03:15:33','WIN-WS089','10.10.14.22','CORP\\jsmith','update.exe'],
    ]
  },
  'ck-t1003': {
    execTime:'0.6s', count:5,
    cols:['_time','host','SourceImage','GrantedAccess','user'],
    riskCol:-1,
    rows:[
      ['03:14:00','WIN-WS089','rundll32.exe','0x1fffff','CORP\\jsmith'],
      ['03:15:01','WIN-WS089','powershell.exe','0x1fffff','CORP\\jsmith'],
      ['22:48:33','WIN-DC01','msiexec.exe','0x1fffff','CORP\\admin'],
    ]
  },
  'ck-t1558': {
    execTime:'1.3s', count:3,
    cols:['_time','Account','src_ip','spn_count','risk'],
    riskCol:4,
    rows:[
      ['02:14:07','jsmith@CORP','10.10.14.22','11','CRITICAL'],
      ['02:16:44','lchen@CORP','10.10.11.54','4','MED'],
      ['02:18:02','bwalker@CORP','10.10.12.83','5','HIGH'],
    ]
  },
  'ck-t1071': {
    execTime:'2.1s', count:2,
    cols:['_time','src_ip','dest_ip','ja3','connections','jitter'],
    riskCol:-1,
    rows:[
      ['03:00–03:30','10.10.14.22','185.220.101.47','769c10b0…','47','1.8s'],
      ['03:30–04:00','10.10.14.22','185.220.101.47','1aa7bf8b…','12','1.4s'],
    ]
  },
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

renderHuntReport('041');
renderHuntPivot('041');
renderHuntObserve('041');
renderSimilarHunts('041');
renderLearnPastHunts();
renderPostingAs();

// ── Init repo list — called from kb-tab.js after all scripts load ──

// ── Live progress ──
let rv = 67;
setInterval(() => {
  rv = Math.min(100, rv + Math.random() * .5);
  document.querySelectorAll('.pf-recon').forEach(e => e.style.width = rv + '%');
}, 1400);

// ════════════════════════════════════════
// ENVIRONMENT CONTEXT  (MCP tool)
// ════════════════════════════════════════
// envData + crownJewels — defined at top of this file; overwritten at runtime from kb/environment.md

// ── Render helpers ──
function _ecPh(v) {
  return (v && String(v).trim()) ? String(v) : '<span style="color:var(--muted);font-style:italic;">not configured</span>';
}
function _ecKv(label, val) {
  return `<div style="display:flex;gap:8px;padding:5px 0;border-bottom:1px solid var(--border);font-size:12px;"><span style="color:var(--sub);width:150px;flex-shrink:0;">${label}</span><span style="color:var(--text);word-break:break-all;">${_ecPh(val)}</span></div>`;
}
function _ecCard(title, icon, content) {
  return `<div style="background:var(--s2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 14px;margin-bottom:12px;">
    <div class="rb-section-head" style="margin-bottom:10px;"><span class="rb-section-icon">${icon}</span>${title}</div>
    ${content}
  </div>`;
}

function renderEcOverview() {
  const m    = envData.meta || {};
  const mon  = envData.monitoring || {};
  const siem = mon.siem || {};
  const identity = mon.identity || {};
  const ttps = envData.priorityTtps || {};
  const ts   = envData.techStack || {};

  document.getElementById('ec-overview-meta').innerHTML = `
    <div style="display:flex;gap:20px;flex-wrap:wrap;background:var(--s2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 14px;">
      <div style="font-size:11px;color:var(--sub);">Last Updated <span style="color:var(--text);font-weight:600;">${m.lastUpdated || '—'}</span></div>
      <div style="font-size:11px;color:var(--sub);">Review Cadence <span style="color:var(--text);font-weight:600;">${m.reviewCadence || '—'}</span></div>
      <div style="font-size:11px;color:var(--sub);">Maintained by <span style="color:var(--text);font-weight:600;">${m.maintainedBy || '—'}</span></div>
    </div>`;

  const siemName  = siem.platform || 'SIEM';
  const idxCount  = (siem.indexes || []).length;
  const eids      = (identity.eventIds || []).length;
  const tactics   = (ttps.tactics || []).length;
  const gapsCount = (envData.gaps || []).filter(g => g.value && g.value.trim()).length;
  const osServers = ((ts.os || {}).servers || []).length;
  const retention = siem.retention ? siem.retention.split(',')[0] : '—';

  document.getElementById('ec-overview-cards').innerHTML = `
    <div class="stat-card c-blue" style="padding:12px 14px;">
      <div class="label">SIEM Indexes</div>
      <div class="val" style="font-size:22px;">${idxCount}</div>
      <div class="note">${siemName.length > 38 ? siemName.slice(0,38)+'…' : siemName}</div>
    </div>
    <div class="stat-card c-teal" style="padding:12px 14px;">
      <div class="label">Identity Event IDs</div>
      <div class="val" style="font-size:22px;">${eids}</div>
      <div class="note">${identity.provider || 'Identity provider'}</div>
    </div>
    <div class="stat-card c-yellow" style="padding:12px 14px;">
      <div class="label">Priority Tactics</div>
      <div class="val" style="font-size:22px;">${tactics}</div>
      <div class="note">Active threat model</div>
    </div>
    <div class="stat-card c-${gapsCount > 0 ? 'red' : 'green'}" style="padding:12px 14px;">
      <div class="label">Documented Gaps</div>
      <div class="val" style="font-size:22px;">${gapsCount}</div>
      <div class="note">${gapsCount > 0 ? 'Blind spots identified' : 'None documented'}</div>
    </div>
    <div class="stat-card c-indigo" style="padding:12px 14px;">
      <div class="label">Server OS Variants</div>
      <div class="val" style="font-size:22px;">${osServers}</div>
      <div class="note">Monitored OS types</div>
    </div>
    <div class="stat-card c-green" style="padding:12px 14px;">
      <div class="label">Log Retention</div>
      <div class="val" style="font-size:16px;margin-top:4px;line-height:1.2;">${retention}</div>
      <div class="note">Hot/warm storage</div>
    </div>`;
}

function renderEcTools() {
  const mon      = envData.monitoring || {};
  const siem     = mon.siem || {};
  const edr      = mon.edr || {};
  const net      = mon.network || {};
  const cloud    = mon.cloud || {};
  const identity = mon.identity || {};
  const other    = mon.other || {};
  let html = '';

  // SIEM
  let siemContent = _ecKv('Platform', siem.platform) + _ecKv('Version', siem.version) + _ecKv('Retention', siem.retention);
  if ((siem.queryAccess || []).length) {
    siemContent += `<div style="font-size:11px;color:var(--sub);margin-top:8px;margin-bottom:4px;">Query Access</div>`;
    siemContent += siem.queryAccess.map(q => `<div style="font-size:11px;color:var(--text);padding:2px 0;">› ${q}</div>`).join('');
  }
  if ((siem.indexes || []).length) {
    siemContent += `<div style="font-size:11px;color:var(--sub);margin-top:8px;margin-bottom:4px;">Indexes</div>`;
    siemContent += siem.indexes.map(ix => `<div style="display:flex;justify-content:space-between;gap:8px;font-size:11px;padding:3px 0;border-bottom:1px solid var(--border);"><code style="color:var(--indigo);">${ix.name}</code><span style="color:var(--muted);">${ix.desc}</span></div>`).join('');
  }
  if (siem.fields && Object.keys(siem.fields).length) {
    siemContent += `<div style="font-size:11px;color:var(--sub);margin-top:8px;margin-bottom:4px;">Key Fields</div>`;
    Object.entries(siem.fields).forEach(([src, fields]) => {
      siemContent += `<div style="font-size:11px;margin-bottom:4px;"><span style="color:var(--text);font-weight:600;">${src}: </span><span style="color:var(--muted);font-family:monospace;">${fields.join(', ')}</span></div>`;
    });
  }
  html += _ecCard('SIEM / Log Aggregation', '🟠', siemContent);

  // Identity
  let idContent = _ecKv('Provider', identity.provider) + _ecKv('Domain Controllers', identity.dcs) + _ecKv('MFA', identity.mfa) + _ecKv('PAM', identity.pam);
  if ((identity.eventIds || []).length) {
    idContent += `<div style="font-size:11px;color:var(--sub);margin-top:8px;margin-bottom:4px;">Monitored Event IDs</div>`;
    idContent += identity.eventIds.map(e => `<div style="display:flex;gap:8px;font-size:11px;padding:3px 0;border-bottom:1px solid var(--border);"><code style="color:var(--indigo);width:40px;flex-shrink:0;">${e.id}</code><span style="color:var(--sub);">${e.desc}</span></div>`).join('');
  }
  html += _ecCard('Identity & Active Directory', '🆔', idContent);

  // EDR
  html += _ecCard('Endpoint Detection & Response', '🖥️',
    _ecKv('Product', edr.product) + _ecKv('Version', edr.version) + _ecKv('Deployment', edr.deployment) + _ecKv('Telemetry', edr.telemetry));

  // Network
  html += _ecCard('Network Monitoring', '🌐',
    _ecKv('Firewalls', net.firewalls) + _ecKv('IDS/IPS', net.idsIps) + _ecKv('Flow Data', net.flowData) + _ecKv('PCAP', net.pcap));

  // Cloud
  html += _ecCard('Cloud Coverage', '☁️',
    _ecKv('Providers', cloud.providers) + _ecKv('Services', cloud.services));

  // Other
  html += _ecCard('Other Tools', '🔧',
    _ecKv('Vuln Scanners', other.vulnScanners) + _ecKv('Asset Mgmt', other.assetMgmt) + _ecKv('Threat Intel', other.threatIntel) + _ecKv('SOAR', other.soar));

  document.getElementById('ec-tools-body').innerHTML = html;
}

function renderEcStack() {
  const ts    = envData.techStack || {};
  const os    = ts.os || {};
  const net   = ts.networking || {};
  const infra = ts.infrastructure || {};
  const apps  = ts.apps || {};
  const dev   = ts.dev || {};
  const dbs   = ts.databases || {};
  let html = '';

  // OS
  let osContent = '';
  if ((os.servers || []).length) {
    osContent += `<div style="font-size:11px;color:var(--sub);margin-bottom:4px;">Servers</div>`;
    osContent += os.servers.map(s => `<div style="font-size:11px;padding:2px 0;color:var(--text);">› ${s}</div>`).join('');
    osContent += '<div style="margin-bottom:8px;"></div>';
  }
  if ((os.workstations || []).length) {
    osContent += `<div style="font-size:11px;color:var(--sub);margin-bottom:4px;">Workstations</div>`;
    osContent += os.workstations.map(s => `<div style="font-size:11px;padding:2px 0;color:var(--text);">› ${s}</div>`).join('');
    osContent += '<div style="margin-bottom:8px;"></div>';
  }
  if (!osContent) osContent = _ecKv('Servers', '') + _ecKv('Workstations', '');
  osContent += _ecKv('Mobile', os.mobile);
  html += _ecCard('Operating Systems', '🖥️', osContent);

  // Networking
  html += _ecCard('Networking', '🌐',
    _ecKv('Architecture', net.architecture) + _ecKv('Load Balancers', net.loadBalancers) + _ecKv('DNS', net.dns) + _ecKv('VPN', net.vpn) + _ecKv('Jump Boxes', net.jumpBoxes));

  // Infrastructure
  html += _ecCard('Infrastructure', '🏗️',
    _ecKv('Cloud', infra.cloud) + _ecKv('Containers', infra.containers) + _ecKv('CI/CD', infra.cicd));

  // Apps
  html += _ecCard('Applications', '📱',
    _ecKv('Email', apps.email) + _ecKv('Collaboration', apps.collaboration) + _ecKv('File Sharing', apps.fileSharing) + _ecKv('Version Control', apps.versionControl) + _ecKv('Project Mgmt', apps.projectMgmt) + _ecKv('Business Apps', apps.business));

  // Dev
  html += _ecCard('Development', '💻',
    _ecKv('Languages', dev.languages) + _ecKv('Web Frameworks', dev.webFrameworks) + _ecKv('API Frameworks', dev.apiFrameworks));

  // Databases
  html += _ecCard('Databases', '🗄️',
    _ecKv('Relational', dbs.relational) + _ecKv('NoSQL', dbs.nosql) + _ecKv('Caching', dbs.caching) + _ecKv('Warehouse', dbs.warehouse));

  document.getElementById('ec-stack-body').innerHTML = html;
}

function renderEcGaps() {
  const gaps        = envData.gaps || [];
  const ttps        = envData.priorityTtps || {};
  const tactics     = ttps.tactics || [];
  const threatModel = ttps.threatModel || [];
  let html = '';

  const gapsContent = gaps.length
    ? gaps.map(g => {
        const hasVal = g.value && g.value.trim();
        return `<div style="display:flex;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px;align-items:flex-start;">
          <span style="color:var(--sub);width:160px;flex-shrink:0;">${g.label}</span>
          <span style="color:${hasVal ? 'var(--red)' : 'var(--muted)'};font-style:${hasVal ? 'normal' : 'italic'};">${hasVal ? g.value : 'none documented'}</span>
        </div>`;
      }).join('')
    : '<span style="color:var(--muted);font-style:italic;font-size:12px;">No gaps configured</span>';
  html += _ecCard('Gaps & Blind Spots', '🕳️', gapsContent);

  const tacticsContent = tactics.length
    ? tactics.map(t => `<div style="display:flex;align-items:flex-start;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);">
        <code style="color:var(--indigo);font-size:11px;width:58px;flex-shrink:0;">${t.id}</code>
        <div style="flex:1;"><div style="font-size:12px;font-weight:600;color:var(--text);margin-bottom:1px;">${t.name}</div><div style="font-size:11px;color:var(--sub);">${t.desc}</div></div>
      </div>`).join('')
    : '<span style="color:var(--muted);font-style:italic;font-size:12px;">No tactics configured</span>';
  html += _ecCard('Priority Tactics (MITRE ATT&CK)', '🎯', tacticsContent);

  const tmContent = threatModel.length
    ? threatModel.map(t => `<div style="display:flex;gap:8px;align-items:flex-start;padding:5px 0;font-size:12px;border-bottom:1px solid var(--border);">
        <span style="color:var(--red);flex-shrink:0;">›</span><span style="color:var(--text);">${t}</span>
      </div>`).join('')
    : '<span style="color:var(--muted);font-style:italic;font-size:12px;">No threat model configured</span>';
  html += _ecCard('Threat Model', '⚔️', tmContent);

  document.getElementById('ec-gaps-body').innerHTML = html;
}

function renderEcMaint() {
  const maint     = envData.maintenance || {};
  const checklist = maint.checklist || [];
  const changeLog = maint.changeLog || [];
  let html = '';

  const checkContent = checklist.length
    ? checklist.map(item => `<div style="display:flex;align-items:flex-start;gap:9px;padding:5px 0;font-size:12px;border-bottom:1px solid var(--border);">
        <span style="color:var(--muted);flex-shrink:0;">☐</span><span style="color:var(--text);">${item}</span>
      </div>`).join('')
    : '<span style="color:var(--muted);font-style:italic;font-size:12px;">No checklist items</span>';
  html += _ecCard('Maintenance Checklist', '✅', checkContent);

  const clContent = changeLog.length
    ? changeLog.map(e => `<div style="display:flex;gap:12px;align-items:flex-start;padding:5px 0;border-bottom:1px solid var(--border);font-size:12px;">
        <span style="color:var(--indigo);font-family:monospace;white-space:nowrap;flex-shrink:0;">${e.date}</span>
        <span style="color:var(--sub);">${e.note}</span>
      </div>`).join('')
    : '<span style="color:var(--muted);font-style:italic;font-size:12px;">No changes logged</span>';
  html += _ecCard('Change Log', '📋', clContent);

  document.getElementById('ec-maint-body').innerHTML = html;
}

// ── Crown Jewels ──
// crownJewels — see kb/environment.js

function buildCrownJewelsHtml() {
  const expDot = (e) => `<span class="cj-exp-dot ${e}"></span>`;
  const expLabel = { high:'In current hunt scope', medium:'Indirectly exposed', low:'Not currently exposed' };
  const t0 = crownJewels.assets.filter(a=>a.tier===0);
  const t1 = crownJewels.assets.filter(a=>a.tier===1);
  const inScope = crownJewels.assets.filter(a=>a.exposure==='high'||a.exposure==='medium').length;
  const assetCard = (a, tierCls) => `
      <div class="cj-card ${tierCls}">
        <div class="cj-card-head">
          <span class="cj-icon">${a.icon}</span>
          <span class="cj-name">${a.name}</span>
          <span class="cj-tier-badge ${tierCls}">${tierCls === 'tier0' ? 'Tier-0' : 'Tier-1'}</span>
        </div>
        <div class="cj-card-body">
          <div class="cj-role">${a.role}</div>
          <div class="cj-ip">${a.ip} · ${a.segment}</div>
          <div><div class="cj-blast-lbl">Blast Radius</div><div class="cj-blast">${a.blast}</div></div>
          <div class="cj-exposure">
            ${expDot(a.exposure)}<span class="cj-exp-label">${expLabel[a.exposure]}</span>
            ${a.ttp ? `<span class="cj-exp-ttp" style="margin-left:auto;">${a.ttp}</span>` : ''}
          </div>
        </div>
      </div>`;
  const emptyNote = (label) => `<div style="color:var(--muted);font-size:11px;font-style:italic;padding:12px 0;">${label}</div>`;
  return `
    <div class="cj-summary-strip">
      <div class="cj-sum-item"><div class="cj-sum-val" style="color:var(--red);">${t0.length}</div><div class="cj-sum-lbl">Tier-0 assets</div></div>
      <div class="cj-sum-item"><div class="cj-sum-val" style="color:var(--orange);">${t1.length}</div><div class="cj-sum-lbl">Tier-1 assets</div></div>
      <div class="cj-sum-item"><div class="cj-sum-val">${crownJewels.accounts.length}</div><div class="cj-sum-lbl">Critical accounts</div></div>
      <div class="cj-sum-item"><div class="cj-sum-val" style="color:var(--yellow);">${inScope}</div><div class="cj-sum-lbl">In hunt scope</div></div>
    </div>
    <div class="cj-section-head"><span style="color:var(--red);">●</span> Tier-0 — Domain-Level Crown Jewels</div>
    <div class="cj-grid">${t0.length ? t0.map(a=>assetCard(a,'tier0')).join('') : emptyNote('No Tier-0 assets defined — add them to kb/environment.md')}</div>
    <div class="cj-section-head" style="margin-top:16px;"><span style="color:var(--orange);">●</span> Tier-1 — High-Value Infrastructure</div>
    <div class="cj-grid">${t1.length ? t1.map(a=>assetCard(a,'tier1')).join('') : emptyNote('No Tier-1 assets defined — add them to kb/environment.md')}</div>
    <div class="cj-section-head" style="margin-top:16px;"><span style="color:var(--yellow);">●</span> Critical Accounts</div>
    <div class="cj-account-list">
      ${crownJewels.accounts.length ? crownJewels.accounts.map(a=>`
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
      </div>`).join('') : emptyNote('No critical accounts defined — add them to kb/environment.md')}
    </div>`;
}

function renderCrownJewels() {
  const pane = document.getElementById('ec-pane-crownJewels');
  if (!pane) return;
  pane.innerHTML = buildCrownJewelsHtml();
}

// ── Open / close / tab switch ──
function openEnvContext(tab) {
  renderEcOverview();
  renderEcTools();
  renderEcStack();
  renderCrownJewels();
  switchEcTab(tab || 'overview');
  document.getElementById('ec-overlay').classList.add('open');

  // Feed entry
  const agentFeed = document.getElementById('agent-feed');
  if (agentFeed) {
    const el = document.createElement('div');
    el.className = 'feed-entry fe-env';
    const _idxN = (((envData.monitoring || {}).siem || {}).indexes || []).length;
    const _tacN = ((envData.priorityTtps || {}).tactics || []).length;
    el.innerHTML = `<span class="fe-prefix">🏗️</span>
      <div class="fe-body"><b>EnvCtx</b> → <code style="font-size:10px;color:var(--indigo);">get_environment()</code> — ${_idxN} SIEM indexes · ${_tacN} priority tactics loaded</div>`;
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

function filterEcSegments(v) {}
function filterEcAssets(v)   {}
function filterEcAccounts(v) {}

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

