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
  // Spaced to let each step's feed entries stream before the next fires
  const steps = [
    { delay:  6000, step: 1, stage: 'stage-1' },
    { delay: 14000, step: 2, stage: 'stage-2' },
    { delay: 23000, step: 3, stage: 'stage-3' },
    { delay: 34000, step: 4, stage: 'stage-4' },
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
  }, 50000);
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

function selectModel(el, name, meta) {
  document.querySelectorAll('.model-menu-item').forEach(i => i.classList.remove('active-model'));
  el.classList.add('active-model');
  const lbl = document.getElementById('model-badge-label');
  if (lbl) lbl.textContent = name;
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

renderHuntReport('041');
renderHuntPivot('041');
renderHuntObserve('041');
renderSimilarHunts('041');
renderLearnPastHunts();
renderPostingAs();

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
// envData + crownJewels — defined at top of this file; overwritten at runtime from kb/environment.md

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

